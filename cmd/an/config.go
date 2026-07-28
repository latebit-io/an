package main

import (
	"fmt"
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
	OidcAuthCodeExpireInSeconds int
	OidcClientID                string
	OidcClientSecret            string
	OidcCryptoKey               string
	OidcEnabled                 bool
	OidcInsecure                bool
	OidcPostLogoutRedirectURIs  []string
	OidcRedirectURIs            []string
	OidcSessionExpireInSeconds  int
	PasswordCost                int
	Port                        int
	PublicBaseURL               string
	RefreshTokenExpireInSeconds int
	RequestsPerSecond           int
	ResetTokenExpireInSeconds   int
}

// minCryptoKeyLength is the shortest OIDC_CRYPTO_KEY accepted. The value is
// stretched to 32 bytes with sha256, which normalises the length but adds
// no entropy, so the input has to carry it.
const minCryptoKeyLength = 32

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

	// The OIDC provider surface. It stays off until a client is
	// configured: an is an api-key service first, an issuer second.
	config.PublicBaseURL = strings.TrimSuffix(getEnv("PUBLIC_BASE_URL", ""), "/")
	config.OidcClientID = getEnv("OIDC_CLIENT_ID", "")
	config.OidcClientSecret = getEnv("OIDC_CLIENT_SECRET", "")
	config.OidcCryptoKey = getEnv("OIDC_CRYPTO_KEY", "")
	config.OidcRedirectURIs = getEnvAsStringSlice("OIDC_REDIRECT_URIS", []string{})
	config.OidcPostLogoutRedirectURIs = getEnvAsStringSlice("OIDC_POST_LOGOUT_REDIRECT_URIS",
		[]string{})
	config.OidcAuthCodeExpireInSeconds = getEnvAsInt("OIDC_AUTH_CODE_EXPIRE_IN_SECONDS", 300)
	config.OidcSessionExpireInSeconds = getEnvAsInt("OIDC_SESSION_EXPIRE_IN_SECONDS", 43200)
	config.OidcInsecure = getEnv("OIDC_INSECURE", "false") == "true"
	// Redirect URIs are part of the predicate: with none registered every
	// /authorize is refused, so a surface mounted without them is a
	// provider that cannot log anyone in and says nothing about why.
	config.OidcEnabled = config.PublicBaseURL != "" && config.OidcClientID != "" &&
		config.OidcClientSecret != "" && config.OidcCryptoKey != "" &&
		len(config.OidcRedirectURIs) > 0

	if config.OidcEnabled && len(config.OidcCryptoKey) < minCryptoKeyLength {
		return nil, fmt.Errorf(
			"OIDC_CRYPTO_KEY must be at least %d characters of random data; it encrypts "+
				"authorization codes and bearer tokens, and hashing does not rescue a guessable "+
				"value (generate one with: openssl rand -hex 32)", minCryptoKeyLength)
	}

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
	values := strings.Split(valueStr, ",")
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		// Redirect URIs and origins are matched exactly, so a space after a
		// comma would otherwise be a registered URI nobody can match.
		if value = strings.TrimSpace(value); value != "" {
			trimmed = append(trimmed, value)
		}
	}
	return trimmed
}
