package main

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"sync"
	"watchAlert/alert"
	"watchAlert/config"
	"watchAlert/internal/cache"
	"watchAlert/internal/ctx"
	"watchAlert/internal/middleware"
	"watchAlert/internal/models"
	"watchAlert/internal/repo"
	"watchAlert/internal/routers"
	v1 "watchAlert/internal/routers/v1"
	"watchAlert/internal/services"
	"watchAlert/pkg/ai"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/gin-gonic/gin"
	"github.com/zeromicro/go-zero/core/logc"
	"golang.org/x/sync/errgroup"
)

var Version string

func main() {
	// 初始化配置
	config.InitConfig(Version)
	logc.Info(context.Background(), "服务启动，端口: "+config.Application.Server.Port)

	// 初始化 Casdoor
	cfg := config.Application.CasdoorConfig
	cert := config.Application.Certificate
	casdoorsdk.InitConfig(
		cfg.Endpoint,
		cfg.ClientID,
		cfg.ClientSecret,
		cert,
		cfg.Organization,
		cfg.ApplicationName,
	)

	initBasic()

	mode := config.Application.Server.Mode
	if mode == "" {
		mode = gin.DebugMode
	}
	gin.SetMode(mode)
	ginEngine := gin.New()

	// ===================== 安全跨域中间件 全局最优先 =====================
	ginEngine.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		// 只允许自己前端域名，可自行增删
		allowList := map[string]bool{
			"http://localhost:3000":  true,
			"http://127.0.0.1:3000":  true,
			"http://localhost:3001":  true,
			"http://127.0.0.1:3001":  true,
		}

		// 仅白名单域名赋予跨域头
		if allowList[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE")
			c.Header("Access-Control-Allow-Headers", "Origin,Content-Type,Authorization,X-Requested-With,TenantID")
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// 预检OPTIONS直接返回200
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusOK)
			return
		}
		c.Next()
	})
	// ===================================================================

	// 其他全局中间件
	ginEngine.Use(
		middleware.GinZapLogger(),
		gin.Recovery(),
		middleware.LoggingMiddleware(),
	)

	// 注册Casdoor路由
	services.RegisterCasdoorGinRoutes(ginEngine)

	// 注册业务路由
	initRouter(ginEngine)

	go func() {
		panic(http.ListenAndServe("localhost:9999", nil))
	}()

	err := ginEngine.Run(":" + config.Application.Server.Port)
	if err != nil {
		panic(fmt.Sprintf("服务启动失败: %s", err.Error()))
	}
}

func initRouter(engine *gin.Engine) {
	routers.HealthCheck(engine)
	v1.Router(engine)
}

func initBasic() {
	dbRepo := repo.NewRepoEntry()
	rCache := cache.NewEntryCache()
	ctx := ctx.NewContext(context.Background(), dbRepo, rCache)

	services.NewServices(ctx)
	services.InitCasdoorService(ctx)
	alert.Initialize(ctx)
	importClientPools(ctx)
	go pushMuteRuleToRedis()

	r, err := ctx.DB.Setting().Get()
	if err != nil {
		logc.Error(ctx.Ctx, fmt.Sprintf("加载系统设置失败: %s", err.Error()))
		return
	}

	if r.AuthType != nil && *r.AuthType == models.SettingLdapAuth {
		const mark = "SyncLdapUserJob"
		c, cancel := context.WithCancel(context.Background())
		ctx.ContextMap[mark] = cancel
		go services.LdapService.SyncUsersCronjob(c, r.LdapConfig)
	}

	if r.AiConfig.GetEnable() {
		client, err := ai.NewAiClient(&r.AiConfig)
		if err != nil {
			logc.Error(ctx.Ctx, fmt.Sprintf("创建 Ai 客户端失败: %s", err.Error()))
			return
		}
		ctx.Redis.ProviderPools().SetClient("AiClient", client)
	}
}

func importClientPools(ctx *ctx.Context) {
	list, err := ctx.DB.Datasource().List("", "", "", "")
	if err != nil {
		logc.Error(ctx.Ctx, err.Error())
		return
	}
	g := new(errgroup.Group)
	for _, datasource := range list {
		ds := datasource
		if !ds.GetEnabled() {
			continue
		}
		g.Go(func() error {
			err := services.DatasourceService.WithAddClientToProviderPools(ds)
			if err != nil {
				logc.Error(ctx.Ctx, fmt.Sprintf("添加到 Client 存储池失败, err: %s", err.Error()))
				return err
			}
			return nil
		})
	}
}

func pushMuteRuleToRedis() {
	list, _, err := ctx.DB.Silence().List("", "", "", "all", models.Page{
		Index: 0,
		Size:  1000,
	})
	if err != nil {
		logc.Errorf(ctx.Ctx, "获取静默规则列表失败, err: %s", err.Error())
		return
	}
	if len(list) == 0 {
		return
	}
	var wg sync.WaitGroup
	wg.Add(len(list))
	for _, silence := range list {
		go func(silence models.AlertSilences) {
			defer wg.Done()
			ctx.Redis.Silence().PushAlertMute(silence)
		}(silence)
	}
	wg.Wait()
	logc.Infof(ctx.Ctx, "所有静默规则加载完毕！")
}