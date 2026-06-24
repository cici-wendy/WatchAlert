package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/gin-gonic/gin"
	"watchAlert/config"
	"watchAlert/internal/ctx"
	"watchAlert/internal/models"
	"watchAlert/internal/types"
	"watchAlert/pkg/tools"
)

type CasdoorService struct {
	ctx *ctx.Context
}

type InterCasdoorService interface {
	SigninHandler(w http.ResponseWriter, r *http.Request)
	UserinfoHandler(w http.ResponseWriter, r *http.Request)
	SyncUserToWatchAlertDBAndLogin(w http.ResponseWriter, r *http.Request)
}

var globalCtx *ctx.Context

// InitCasdoorService 初始化全局上下文
func InitCasdoorService(c *ctx.Context) {
	if c == nil {
		panic("casdoor service init failed: context is nil")
	}
	globalCtx = c
}

// 生成随机密码哈希（和系统原生登录格式一致）
func generateRandomPassword() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// 密码生成失败时使用备用随机字符串，避免程序崩溃
		b = []byte(time.Now().Format("20060102150405") + "casdoor-random")
	}
	raw := base64.StdEncoding.EncodeToString(b)
	// 调用系统原生的密码加密方法，确保格式和本地用户一致
	return tools.GenerateHashPassword(raw)
}

// 前端传入的 Casdoor 用户信息结构
type CasdoorUserInfo struct {
	Sub                 string `json:"sub"`                  // 用户唯一ID → 作为 WatchAlert.UserId
	Iss                 string `json:"iss"`
	Aud                 string `json:"aud"`
	PreferredUsername   string `json:"preferred_username"`   // 用户名
	Name                string `json:"name"`                 // 显示名
	Picture             string `json:"picture"`
	Email               string `json:"email,omitempty"`      // 可选
	Phone               string `json:"phone,omitempty"`      // 可选
}

// 登录请求结构体（和原生登录一致）
type LoginReq struct {
	Password string `json:"password"`
}

// SigninHandler Casdoor OAuth 登录回调处理
// @Summary Casdoor登录回调
// @Description 处理Casdoor OAuth授权码，获取Access Token
// @Tags Casdoor
// @Accept json
// @Produce json
// @Param code query string true "授权码"
// @Param state query string true "状态值"
// @Success 200 {object} map[string]interface{} "status: ok, data: access_token"
// @Failure 400 {string} string "missing code or state"
// @Failure 500 {string} string "get token failed"
// @Router /api/signin [get]
func SigninHandler(w http.ResponseWriter, r *http.Request) {
	// 从 URL Query 获取授权码和状态
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	// 获取Casdoor OAuth Token
	token, err := casdoorsdk.GetOAuthToken(code, state)
	if err != nil {
		errMsg := fmt.Sprintf("GetOAuthToken error: %v", err)
		fmt.Println(errMsg)
		http.Error(w, "get token failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 响应结果
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"data":   token.AccessToken,
	}); err != nil {
		fmt.Printf("encode signin response error: %v\n", err)
	}
}

// UserinfoHandler 获取Casdoor用户信息
// @Summary 获取Casdoor用户信息
// @Description 通过Bearer Token解析Casdoor用户信息
// @Tags Casdoor
// @Accept json
// @Produce json
// @Header 200 {string} Authorization "Bearer token"
// @Success 200 {object} map[string]interface{} "status: ok, data: user_info"
// @Failure 401 {string} string "authHeader is empty/token is not valid Bearer token/ParseJwtToken() error"
// @Router /api/userinfo [get]
func UserinfoHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "authHeader is empty", http.StatusUnauthorized)
		return
	}

	// 解析Bearer Token
	tokenParts := strings.Split(authHeader, "Bearer ")
	if len(tokenParts) != 2 || tokenParts[1] == "" {
		http.Error(w, "token is not valid Bearer token", http.StatusUnauthorized)
		return
	}

	// 验证并解析JWT Token
	claims, err := casdoorsdk.ParseJwtToken(tokenParts[1])
	if err != nil {
		errMsg := fmt.Sprintf("ParseJwtToken error: %v", err)
		fmt.Println(errMsg)
		http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// 响应用户信息
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"data":   claims.User,
	}); err != nil {
		fmt.Printf("encode userinfo response error: %v\n", err)
	}
}

// SyncUserToWatchAlertDBAndLogin 同步Casdoor用户到本地库并生成系统Token
// @Summary 同步Casdoor用户并登录
// @Description 自动同步用户到本地数据库，生成系统登录Token
// @Tags Casdoor
// @Accept json
// @Produce json
// @Param user body CasdoorUserInfo true "Casdoor用户信息"
// @Success 200 {object} gin.H "code:200, data:{token, identifier, userId}"
// @Failure 400 {string} string "sub or username empty/request body parse error"
// @Failure 500 {string} string "service not initialized/generate token failed/redis set error"
// @Router /api/casdoor/sync-login [post]
func SyncUserToWatchAlertDBAndLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}

	var casUser CasdoorUserInfo
	json.NewDecoder(r.Body).Decode(&casUser)
	r.Body.Close()

	// 1. 查询用户（忽略不存在错误）
	user, _, _ := globalCtx.DB.User().Get(casUser.Sub, "", "", "")

	// 2. 不存在就创建（完全和系统对齐）
	if user.UserId == "" {
		user = models.Member{
			UserId:    casUser.Sub,
			UserName:  casUser.PreferredUsername,
			Password:  tools.GenerateHashPassword("Casdoor123!"),
			Role:      "app",
			CreateBy:  "CASDOOR",
			Tenants:   []string{"tid-d83eabdftbk6514kddr0"},
			CreateAt:  time.Now().Unix(),
		}
		globalCtx.DB.User().Create(user)
	}

	// ==========================================
	// ✅【完全复刻原生登录】这是唯一关键！
	// ==========================================
	loginReq := types.RequestUserLogin{
		Identifier: user.UserName,
		Password:   user.Password,
	}

	// 生成 Token（和官方一模一样）
	token, _ := tools.GenerateToken(user.UserId, loginReq.Identifier, loginReq.Password)

	// 存入 Redis（和官方一模一样）
	jsonStr := tools.JsonMarshalToString(loginReq)
	expire := time.Duration(config.Application.Jwt.Expire) * time.Second
	globalCtx.Redis.Redis().Set("uid-"+user.UserId, jsonStr, expire)

	// 返回（和官方一模一样）
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gin.H{
		"code": 200,
		"data": gin.H{
			"token":      token,
			"identifier": user.UserName,
			"userId":     user.UserId,
		},
	})
}
// RegisterCasdoorGinRoutes 注册Casdoor相关路由到Gin引擎
func RegisterCasdoorGinRoutes(r *gin.Engine) {
	if r == nil {
		panic("gin engine is nil when register casdoor routes")
	}

	// Casdoor OAuth相关路由
	r.POST("/api/signin", func(c *gin.Context) {
		SigninHandler(c.Writer, c.Request)
	})

	r.GET("/api/userinfo", func(c *gin.Context) {
		UserinfoHandler(c.Writer, c.Request)
	})

	// 同步用户并登录路由
	r.POST("/api/casdoor/sync-login", func(c *gin.Context) {
		SyncUserToWatchAlertDBAndLogin(c.Writer, c.Request)
	})
}