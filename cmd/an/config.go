package main

import (
	"os"
	"strconv"
	"strings"
)

type AppConfig struct {
	AccessTokenExpireInSeconds  int
	AllowedOrigins              []string
	Audience                    string
	BootstrapApiKey             string
	CORSEnabled                 bool
	DbConnection                string
	DefaultTenantID             string
	Domain                      string
	GoogleClientID              string
	Issuer                      string
	LockoutDurationInSeconds    int
	MagicCodeExpireInSeconds    int
	MaxFailedAttempts           int
	PasswordCost                int
	Port                        int
	RefreshTokenExpireInSeconds int
	RequestsPerSecond           int
	ResetTokenExpireInSeconds   int
}

func NewAppConfig() (*AppConfig, error) {
	config := &AppConfig{}

	config.Port = getEnvAsInt("PORT", 8080)
	config.DbConnection = getEnv("DB_CONNECTION", "postgres://an:an@localhost:5432/an?sslmode=disable")
	config.Domain = getEnv("DOMAIN", "")
	config.AllowedOrigins = getEnvAsStringSlice("ALLOWED_WEB_ORIGINS", []string{})
	config.BootstrapApiKey = getEnv("BOOTSTRAP_API_KEY", "")
	config.CORSEnabled = getEnv("CORS_ENABLED", "false") == "true"
	config.RequestsPerSecond = getEnvAsInt("REQUESTS_PER_SECOND", 20)
	config.DefaultTenantID = getEnv("DEFAULT_TENANT_ID", "default")
	config.Issuer = getEnv("ISSUER", "an")
	config.Audience = getEnv("AUDIENCE", "an")
	config.AccessTokenExpireInSeconds = getEnvAsInt("ACCESS_TOKEN_EXPIRE_IN_SECONDS", 3600)
	config.RefreshTokenExpireInSeconds = getEnvAsInt("REFRESH_TOKEN_EXPIRE_IN_SECONDS", 86400)
	config.PasswordCost = getEnvAsInt("PASSWORD_COST", 12)
	config.MaxFailedAttempts = getEnvAsInt("MAX_FAILED_ATTEMPTS", 5)
	config.LockoutDurationInSeconds = getEnvAsInt("LOCKOUT_DURATION_IN_SEC", 900)
	config.MagicCodeExpireInSeconds = getEnvAsInt("MAGIC_CODE_EXPIRE_IN_SECONDS", 600)
	config.ResetTokenExpireInSeconds = getEnvAsInt("RESET_TOKEN_EXPIRE_IN_SECONDS", 3600)
	config.GoogleClientID = getEnv("GOOGLE_CLIENT_ID", "")

	return config, nil
}

func getEnv(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsStringSlice(key string, defaultValue []string) []string {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	return strings.Split(valueStr, ",")
}
