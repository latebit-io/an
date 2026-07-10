package auth

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/api/problem"
	"github.com/latebit-io/an/internal/apikeys"
	"github.com/latebit-io/an/internal/utils"
)

// HeaderApiKey carries the api key on every request.
const HeaderApiKey = "X-AN-API-KEY"

const (
	contextTenant = "an.tenant"
	contextRoot   = "an.root"
)

// Middleware authenticates every request (except /health and /.well-known/)
// with an api key.
// The bootstrap key (env) is the root credential: it operates on any tenant
// and is the only key that can manage api keys. Tenant keys are locked to
// their tenant regardless of the tenantId in the request body.
func Middleware(service apikeys.ApiKeyService, bootstrapKey string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			path := c.Request().URL.Path
			if path == "/health" || strings.HasPrefix(path, "/.well-known/") {
				return next(c)
			}

			token := c.Request().Header.Get(HeaderApiKey)
			if token == "" {
				return unauthorized(c)
			}

			if utils.SafeCompare(token, bootstrapKey) {
				c.Set(contextRoot, true)
				return next(c)
			}

			tenantID, err := service.Authenticate(c.Request().Context(), token)
			if err != nil {
				return unauthorized(c)
			}
			c.Set(contextTenant, tenantID)
			return next(c)
		}
	}
}

// EffectiveTenant resolves the tenant a request operates on: a tenant key
// forces its own tenant, the root key uses the requested one (defaulted).
func EffectiveTenant(c *echo.Context, requested string) string {
	if tenantID, ok := c.Get(contextTenant).(string); ok && tenantID != "" {
		return tenantID
	}
	return utils.TenantOrDefault(requested)
}

// IsRoot reports whether the request authenticated with the bootstrap key.
func IsRoot(c *echo.Context) bool {
	root, ok := c.Get(contextRoot).(bool)
	return ok && root
}

func unauthorized(c *echo.Context) error {
	return c.JSON(http.StatusUnauthorized, problem.NewUnauthorized("a valid api key is required"))
}
