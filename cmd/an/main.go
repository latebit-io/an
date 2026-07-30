package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	accountsapi "github.com/latebit-io/an/api/accounts"
	apikeysapi "github.com/latebit-io/an/api/apikeys"
	"github.com/latebit-io/an/api/auth"
	authenticateapi "github.com/latebit-io/an/api/authenticate"
	"github.com/latebit-io/an/api/health"
	jwksapi "github.com/latebit-io/an/api/jwks"
	oidcapi "github.com/latebit-io/an/api/oidc"
	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/apikeys"
	"github.com/latebit-io/an/internal/authn"
	"github.com/latebit-io/an/internal/db"
	oidcinternal "github.com/latebit-io/an/internal/oidc"
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
	// Every surface an account can be signed in on has to be revocable
	// together: a credential change that ends the api-key sessions but
	// leaves the OIDC ones live has not ended anything.
	revokers := []accounts.SessionRevoker{sessionRepository}
	if config.OidcEnabled {
		revokers = append(revokers, oidcinternal.NewSessionRevoker(
			oidcinternal.NewPostgresBrowserSessionRepository(pool),
			oidcinternal.NewPostgresTokenRepository(pool)))
	}
	accountService := accounts.NewDefaultAccountService(accountRepository, passwordResetRepository,
		revokers, failedAttemptRepository, txManager, config.PasswordCost,
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
		tokenizer, txManager, config.PasswordCost)
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

	oidcRepositories, err := oidcSetting(ctx, service, config, pool, accountRepository,
		signingKeyService, authenticationService, logger)
	if err != nil {
		panic(err)
	}

	corsSetting(service, config, logger)
	apiKeySetting(service, config, apiKeyService, logger)

	go janitor(ctx, logger, tokenizer, sessionRepository, logonCodeRepository,
		passwordResetRepository, failedAttemptRepository, oidcRepositories)

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
// (expiry is enforced on read; this only reclaims dead rows), drops
// failed-attempt rows untouched for a day, and re-reads the signing keys so
// a rotation reaches a running service.
func janitor(ctx context.Context, logger *slog.Logger, tokenizer tokens.Tokenizer,
	sessions authn.SessionRepository, codes authn.LogonCodeRepository,
	resets accounts.PasswordResetRepository, attempts authn.FailedAttemptRepository,
	oidcRepositories *oidcRepositories) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := tokenizer.ReloadKeys(ctx); err != nil {
			logger.Error("janitor: signing keys", "error", err)
		}
		oidcRepositories.reloadKeys(ctx, logger)
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
		expiredOidc := oidcRepositories.deleteExpired(ctx, logger)
		logger.Info("janitor swept", "sessions", expiredSessions, "logonCodes", expiredCodes,
			"passwordResets", expiredResets, "failedAttempts", staleAttempts, "oidc", expiredOidc)
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
	// The OIDC surface is exempt: browsers and relying parties cannot send
	// an api key, so those routes authenticate the client or the user.
	public := []auth.PublicPath{}
	if config.OidcEnabled {
		public = append(public, oidcapi.IsProviderPath)
	}
	service.Use(auth.Middleware(apiKeyService, config.BootstrapApiKey, public...))
	logger.Info("api key auth enabled")
}

// oidcRepositories groups the OIDC stores so the janitor can sweep them.
// It is nil when the provider surface is off.
type oidcRepositories struct {
	authRequests oidcinternal.AuthRequestRepository
	tokens       oidcinternal.TokenRepository
	sessions     oidcinternal.BrowserSessionRepository
	storage      *oidcinternal.Storage
}

// reloadKeys re-reads the signing keys the provider caches, so a rotation
// reaches the OIDC surface on the same sweep it reaches the api-key one.
func (r *oidcRepositories) reloadKeys(ctx context.Context, logger *slog.Logger) {
	if r == nil {
		return
	}
	if err := r.storage.ReloadKeys(ctx); err != nil {
		logger.Error("janitor: oidc signing keys", "error", err)
	}
}

func (r *oidcRepositories) deleteExpired(ctx context.Context, logger *slog.Logger) int64 {
	if r == nil {
		return 0
	}
	var swept int64
	expiredRequests, err := r.authRequests.DeleteExpired(ctx)
	if err != nil {
		logger.Error("janitor: oidc auth requests", "error", err)
	}
	swept += expiredRequests
	expiredTokens, err := r.tokens.DeleteExpired(ctx)
	if err != nil {
		logger.Error("janitor: oidc tokens", "error", err)
	}
	swept += expiredTokens
	expiredSessions, err := r.sessions.DeleteExpired(ctx)
	if err != nil {
		logger.Error("janitor: oidc browser sessions", "error", err)
	}
	return swept + expiredSessions
}

// oidcSetting mounts the OIDC provider surface when it is configured. The
// service runs without it: an is an api-key service that also speaks OIDC,
// not the other way round.
func oidcSetting(ctx context.Context, service *echo.Echo, config *AppConfig, pool *pgxpool.Pool,
	accountRepository accounts.AccountRepository, signingKeys tokens.SigningKeyService,
	authentication authn.AuthenticationService, logger *slog.Logger) (*oidcRepositories, error) {
	if !config.OidcEnabled {
		logger.Info("oidc provider disabled",
			"reason", "PUBLIC_BASE_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_CRYPTO_KEY are all required")
		return nil, nil
	}
	cryptoKey := sha256.Sum256([]byte(config.OidcCryptoKey))

	authRequestRepository := oidcinternal.NewPostgresAuthRequestRepository(pool)
	tokenRepository := oidcinternal.NewPostgresTokenRepository(pool)
	browserSessionRepository := oidcinternal.NewPostgresBrowserSessionRepository(pool)

	configured := oidcinternal.NewStaticClientRegistry(&oidcinternal.StaticClient{
		ID:                     config.OidcClientID,
		SecretHash:             utils.Sha256Hex(config.OidcClientSecret),
		RedirectURIs:           config.OidcRedirectURIs,
		PostLogoutRedirectURIs: config.OidcPostLogoutRedirectURIs,
		FirstParty:             true,
		IDTokenLifetime:        time.Duration(config.AccessTokenExpireInSeconds) * time.Second,
		ClockSkewTolerance:     0,
	})
	// Clients registered through the admin API resolve behind the configured
	// one, so a deployment that names a single client in its environment keeps
	// working and nothing has to be migrated into the table.
	clientRepository := oidcinternal.NewPostgresClientRepository(pool)
	registry := oidcinternal.NewRegistryClientRegistry(configured, clientRepository)

	// Registering a client mints a credential, so it sits with accounts and
	// api keys behind the bootstrap key rather than on the provider surface.
	oidcapi.ClientRoutes(service, oidcapi.NewClientHandler(clientRepository))

	storage := oidcinternal.NewStorage(authRequestRepository, tokenRepository, accountRepository,
		signingKeys, registry,
		func(tenantID, authRequestID string) string {
			return oidcapi.LoginURL(config.PublicBaseURL, tenantID, authRequestID)
		},
		time.Duration(config.OidcAuthCodeExpireInSeconds)*time.Second,
		time.Duration(config.AccessTokenExpireInSeconds)*time.Second,
		time.Duration(config.RefreshTokenExpireInSeconds)*time.Second)

	if err := storage.ReloadKeys(ctx); err != nil {
		return nil, err
	}

	provider, err := oidcapi.NewProvider(storage, oidcapi.ProviderConfig{
		PublicBaseURL: config.PublicBaseURL,
		CryptoKey:     cryptoKey,
		Insecure:      config.OidcInsecure,
	})
	if err != nil {
		return nil, err
	}
	loginHandler, err := oidcapi.NewLoginHandler(storage, browserSessionRepository, authentication,
		accountRepository, registry, provider, config.PublicBaseURL, !config.OidcInsecure,
		time.Duration(config.OidcSessionExpireInSeconds)*time.Second)
	if err != nil {
		return nil, err
	}
	// The OIDC routes face public traffic, so they get their own limiter
	// bucket instead of sharing the service-wide budget.
	oidcLimiter := middleware.RateLimiter(
		middleware.NewRateLimiterMemoryStore(float64(config.RequestsPerSecond)))
	oidcapi.OidcRoutes(service, provider, loginHandler, config.PublicBaseURL, oidcLimiter)

	logger.Info("oidc provider enabled", "issuer", oidcapi.Issuer(config.PublicBaseURL, config.DefaultTenantID))
	if config.OidcInsecure {
		logger.Warn("OIDC_INSECURE is set — http issuers allowed and cookies are not Secure, development only")
	}
	return &oidcRepositories{
		authRequests: authRequestRepository,
		tokens:       tokenRepository,
		sessions:     browserSessionRepository,
		storage:      storage,
	}, nil
}
