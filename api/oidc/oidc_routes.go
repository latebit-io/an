package oidc

import (
	"slices"

	"github.com/labstack/echo/v5"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// OidcRoutes mounts the provider under the tenant prefix.
//
// The login UI is registered before the catch-all so its static segment
// wins, and everything else (discovery, /authorize, /oauth/token,
// /userinfo, /end_session, /keys) is served by the library through one
// wrapped handler.
//
// These routes are the first exceptions to the api key gate: they are
// browser and relying-party facing and cannot carry X-AN-API-KEY. The token
// and userinfo endpoints authenticate the client instead, and /authorize
// authenticates the user.
func OidcRoutes(e *echo.Echo, provider *op.Provider, handler LoginHandler, publicBaseURL string,
	middleware ...echo.MiddlewareFunc) {
	// Discovery is served ahead of the catch-all so the library's document
	// can be stripped of capabilities this issuer does not have.
	discovery := NewDiscoveryHandler(provider, publicBaseURL)
	e.GET(TenantPathPrefix+":tenantId"+DiscoveryPath, discovery.Discovery, middleware...)

	e.GET(TenantPathPrefix+":tenantId"+LoginPath, handler.Login, middleware...)
	e.POST(TenantPathPrefix+":tenantId"+LoginPath, handler.Submit, middleware...)
	// The advertised end_session_endpoint, with /logout kept as a
	// human-facing alias.
	e.GET(TenantPathPrefix+":tenantId"+EndSessionPath, handler.Logout, middleware...)
	e.POST(TenantPathPrefix+":tenantId"+EndSessionPath, handler.Logout, middleware...)
	e.GET(TenantPathPrefix+":tenantId"+LogoutPath, handler.Logout, middleware...)

	mounted := echo.WrapHandler(tenantHandler(provider, publicBaseURL, provider))
	e.Any(TenantPathPrefix+":tenantId/*", mounted, middleware...)
}

// providerPaths lists the paths under a tenant prefix that the api key
// middleware must let through unauthenticated. IsProviderPath runs in that
// middleware, so this is a package value rather than a fresh slice per
// request.
var providerPaths = []string{
	DiscoveryPath,
	"/authorize",
	"/authorize/callback",
	"/oauth/token",
	// Introspection is how a resource server validates an opaque
	// access token, which is the only kind this surface issues.
	"/oauth/introspect",
	"/userinfo",
	"/revoke",
	EndSessionPath,
	"/keys",
	LoginPath,
	LogoutPath,
}

// IsProviderPath reports whether a request path belongs to the OIDC
// surface, which is public by design.
func IsProviderPath(path string) bool {
	tenantID, rest := splitTenantPath(path)
	if tenantID == "" {
		return false
	}
	return slices.Contains(providerPaths, rest)
}
