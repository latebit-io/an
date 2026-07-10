package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	accountsapi "github.com/latebit-io/an/api/accounts"
	apikeysapi "github.com/latebit-io/an/api/apikeys"
	"github.com/latebit-io/an/api/auth"
	authenticateapi "github.com/latebit-io/an/api/authenticate"
	"github.com/latebit-io/an/api/health"
	jwksapi "github.com/latebit-io/an/api/jwks"
	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/apikeys"
	"github.com/latebit-io/an/internal/authn"
	"github.com/latebit-io/an/internal/db"
	"github.com/latebit-io/an/internal/social"
	"github.com/latebit-io/an/internal/tenants"
	"github.com/latebit-io/an/internal/tokens"
	"github.com/latebit-io/an/internal/utils"
	"github.com/latebit-io/an/internal/version"
)

func main() {
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	// If the version flag is passed, print the version and exit
	if *versionFlag {
		fmt.Println(version.GetVersionInfo())
		os.Exit(0)
	}

	logger := getLogger()
	fmt.Println(`
  __   ____
 / _\ (  ( \
/    \/    /
\_/\_/\_)__) v1.0.0`)
	err := godotenv.Load()
	if err != nil {
		logger.Warn("no .env file loading from system")
	}

	config, err := NewAppConfig()
	if err != nil {
		panic(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	service := echo.New()
	logger.Info("connecting to postgres", "uri", config.DbConnection)
	pool, err := db.Connect(ctx, config.DbConnection)
	if err != nil {
		panic(err)
	}
	defer pool.Close()

	logger.Info("running migrations")
	if err := db.Migrate(ctx, pool); err != nil {
		panic(err)
	}

	ratelimiter := middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(float64(config.RequestsPerSecond)))
	tenantRepository := tenants.NewPostgresTenantRepository(pool)
	tenantService := tenants.NewDefaultTenantService(tenantRepository)
	err = createDefaultTenantID(ctx, tenantService)
	if err != nil {
		panic(err)
	}
	signingKeyRepository := tokens.NewPostgresSigningKeyRepository(pool)
	signingKeyService := tokens.NewDefaultSigningKeyService(signingKeyRepository)
	if err := signingKeyService.Initialize(ctx); err != nil {
		panic(err)
	}
	tokenizer, err := tokens.NewDefaultTokenizer(ctx, config.Issuer, config.Audience,
		config.AccessTokenExpireInSeconds, config.RefreshTokenExpireInSeconds, signingKeyService)
	if err != nil {
		panic(err)
	}
	jwksHandler := jwksapi.NewJwksHandler(signingKeyService)
	jwksapi.JwksRoutes(service, jwksHandler, ratelimiter)
	txManager := utils.NewPostgresTxManager(pool)
	sessionRepository := authn.NewPostgresSessionRepository(pool)
	failedAttemptRepository := authn.NewPostgresFailedAttemptRepository(pool)
	accountRepository := accounts.NewPostgresAccountRepository(pool)
	passwordResetRepository := accounts.NewPostgresPasswordResetRepository(pool)
	accountService := accounts.NewDefaultAccountService(accountRepository, passwordResetRepository,
		sessionRepository, failedAttemptRepository, txManager, config.PasswordCost,
		time.Duration(config.ResetTokenExpireInSeconds)*time.Second)
	accountHandler := accountsapi.NewAccountHandler(accountService)
	accountsapi.AccountRoutes(service, accountHandler, ratelimiter)
	authenticationService := authn.NewDefaultAuthenticationService(accountRepository,
		sessionRepository, failedAttemptRepository, tokenizer, config.MaxFailedAttempts,
		time.Duration(config.LockoutDurationInSeconds)*time.Second)
	authenticateHandler := authenticateapi.NewAuthenticateHandler(authenticationService)
	authenticateapi.AuthenticateRoutes(service, authenticateHandler, ratelimiter)
	logonCodeRepository := authn.NewPostgresLogonCodeRepository(pool)
	logonCodeService := authn.NewDefaultLogonCodeService(authenticationService, accountRepository,
		logonCodeRepository, time.Duration(config.MagicCodeExpireInSeconds)*time.Second,
		config.PasswordCost)
	logonCodeHandler := authenticateapi.NewLogonCodeHandler(logonCodeService)
	authenticateapi.LogonCodeRoutes(service, logonCodeHandler, ratelimiter)
	socialRepository := social.NewPostgresSocialRepository(pool)
	socialService := social.NewDefaultSocialService(accountRepository, socialRepository,
		tokenizer, config.PasswordCost)
	if config.GoogleClientID != "" {
		googleValidator, err := social.NewGoogleValidator(ctx, config.GoogleClientID)
		if err != nil {
			panic(err)
		}
		socialService.AddValidator(googleValidator)
		logger.Info("google social sign-in enabled")
	}
	socialHandler := authenticateapi.NewSocialHandler(socialService)
	authenticateapi.SocialRoutes(service, socialHandler, ratelimiter)
	apiKeyRepository := apikeys.NewPostgresApiKeyRepository(pool)
	apiKeyService := apikeys.NewDefaultApiKeyService(apiKeyRepository)
	apiKeyHandler := apikeysapi.NewApiKeyHandler(apiKeyService)
	apikeysapi.ApiKeyRoutes(service, apiKeyHandler, ratelimiter)

	corsSetting(service, config, logger)
	apiKeySetting(service, config, apiKeyService, logger)

	go janitor(ctx, logger, sessionRepository, logonCodeRepository, passwordResetRepository,
		failedAttemptRepository)

	healthHandler := health.NewHealthHandler()
	health.HealthRoutes(service, healthHandler)

	start := echo.StartConfig{
		Address:         fmt.Sprintf(":%d", config.Port),
		HideBanner:      true,
		GracefulTimeout: 10 * time.Second,
	}
	if err := start.Start(ctx, service); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error(err.Error())
	}
}

// janitor deletes expired sessions, logon codes and reset tokens hourly
// (expiry is enforced on read; this only reclaims dead rows) and drops
// failed-attempt rows untouched for a day.
func janitor(ctx context.Context, logger *slog.Logger, sessions authn.SessionRepository,
	codes authn.LogonCodeRepository, resets accounts.PasswordResetRepository,
	attempts authn.FailedAttemptRepository) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		expiredSessions, err := sessions.DeleteExpired(ctx)
		if err != nil {
			logger.Error("janitor: sessions", "error", err)
		}
		expiredCodes, err := codes.DeleteExpired(ctx)
		if err != nil {
			logger.Error("janitor: logon codes", "error", err)
		}
		expiredResets, err := resets.DeleteExpired(ctx)
		if err != nil {
			logger.Error("janitor: password resets", "error", err)
		}
		staleAttempts, err := attempts.DeleteStale(ctx, 24*time.Hour)
		if err != nil {
			logger.Error("janitor: failed attempts", "error", err)
		}
		logger.Info("janitor swept", "sessions", expiredSessions, "logonCodes", expiredCodes,
			"passwordResets", expiredResets, "failedAttempts", staleAttempts)
	}
}

func getLogger() *slog.Logger {
	jsonHandler := slog.NewJSONHandler(os.Stderr, nil)
	logger := slog.New(jsonHandler)
	return logger
}

func createDefaultTenantID(ctx context.Context, tenantService tenants.TenantService) error {
	existingTenants, err := tenantService.ListTenants(ctx)
	if err != nil {
		return err
	}

	if len(existingTenants) == 0 {
		return tenantService.CreateDefault(ctx)
	}
	return nil
}

func corsSetting(service *echo.Echo, config *AppConfig, logger *slog.Logger) {
	if !config.CORSEnabled {
		return
	}
	if config.Domain != "" {
		config.AllowedOrigins = append(config.AllowedOrigins, fmt.Sprintf("https://%s", config.Domain))
	}

	service.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: config.AllowedOrigins,
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	logger.Info("cors enabled")
}

func apiKeySetting(service *echo.Echo, config *AppConfig, apiKeyService apikeys.ApiKeyService,
	logger *slog.Logger) {
	if config.BootstrapApiKey == "" {
		logger.Warn("BOOTSTRAP_API_KEY not set — api key auth is DISABLED, all endpoints are open")
		return
	}
	service.Use(auth.Middleware(apiKeyService, config.BootstrapApiKey))
	logger.Info("api key auth enabled")
}
