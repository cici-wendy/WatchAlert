package config

import (
	"log"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type App struct {
	Server        Server        `json:"Server"`
	Database      Database      `json:"Database"`
	Redis         Redis         `json:"Redis"`
	Jwt           Jwt           `json:"Jwt"`
	Jaeger        Jaeger        `json:"Jaeger"`
	CasdoorConfig CasdoorConfig `json:"CasdoorConfig"`
	Certificate   string        `json:"Certificate"`
}

type Server struct {
	Mode           string `json:"mode"`
	Port           string `json:"port"`
	EnableElection bool   `json:"enableElection"`
}

type Database struct {
	Type    string `json:"type"`
	Host    string `json:"host"`
	Port    string `json:"port"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	DBName  string `json:"dbName"`
	Timeout string `json:"timeout"`
	Path    string `json:"path"`
}

type Redis struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Pass     string `json:"pass"`
	Database int    `json:"database"`
}

type Jwt struct {
	Expire int64 `json:"expire"`
}

type Jaeger struct {
	URL string `json:"url"`
}

type CasdoorConfig struct {
	Endpoint     string `json:"endpoint"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Organization string `json:"organization"`
	ApplicationName string `json:"application_name"`
}

type Certificate struct {
	Cert string `json:"cert"`
}

var (
	Application App
	Version     string
	configFile  = "config/config.yaml"
)

func InitConfig(version string) {
	v := viper.New()
	v.SetConfigFile(configFile)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		log.Fatal("配置读取失败:", err)
	}

	// ======================= ✅ 关键代码 =======================
	// 让 Viper 解析 YAML 时支持 json 标签，不用 mapstructure！
	err := v.Unmarshal(&Application, func(dc *mapstructure.DecoderConfig) {
		dc.TagName = "json" // 👈 强制使用 json 标签解析
	})
	// ==========================================================

	if err != nil {
		log.Fatal("配置解析失败:", err)
	}

	Version = version
}