package oidc

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	internaloidc "github.com/latebit-io/an/internal/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// TenantPathPrefix is the path segment the tenant issuer lives under. The
// tenant is in the issuer URL from day one even while one tenant uses it:
// a relying party's configured issuer must match iss exactly, so moving it
// later breaks every registered client.
const TenantPathPrefix = "/t/"

// Paths an serves itself rather than handing to the library.
const (
	// LoginPath is the login UI.
	LoginPath = "/login"
	// EndSessionPath is what discovery advertises as end_session_endpoint,
	// so it is where RP-initiated logout has to answer.
	EndSessionPath = "/end_session"
	// LogoutPath is a human-facing alias for the same handler.
	LogoutPath = "/logout"
)

// ProviderConfig is what the mount needs beyond the storage adapter.
type ProviderConfig struct {
	// PublicBaseURL is the externally reachable origin, without a trailing
	// slash. Issuers are built from it.
	PublicBaseURL string
	// CryptoKey encrypts authorization codes and bearer tokens. Losing it
	// invalidates in-flight codes.
	CryptoKey [32]byte
	// Insecure allows http issuers, for local development and tests only.
	Insecure bool
}

// Issuer builds the issuer URL of one tenant.
func Issuer(publicBaseURL, tenantID string) string {
	return strings.TrimSuffix(publicBaseURL, "/") + TenantPathPrefix + tenantID
}

// LoginURL builds the login page URL of one authorization request. The
// library calls it through Client.LoginURL.
func LoginURL(publicBaseURL, tenantID, authRequestID string) string {
	return fmt.Sprintf("%s%s?authRequestId=%s", Issuer(publicBaseURL, tenantID), LoginPath,
		authRequestID)
}

// NewProvider builds the OpenID provider. The issuer is derived per request
// from the tenant the mount put in the context, so one provider serves
// every tenant.
func NewProvider(storage *internaloidc.Storage, config ProviderConfig) (*op.Provider, error) {
	providerConfig := &op.Config{
		CryptoKey: config.CryptoKey,
		// PKCE with S256 and form-post client authentication. Plain PKCE
		// is not offered.
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       internaloidc.SupportedScopes,
		SupportedClaims: []string{
			"sub", "email", "email_verified", "name", "groups", "aud", "exp", "iat", "iss",
			"auth_time", "nonce",
		},
	}
	issuer := func(insecure bool) (op.IssuerFromRequest, error) {
		return func(r *http.Request) string {
			tenantID, err := internaloidc.TenantFrom(r.Context())
			if err != nil {
				return config.PublicBaseURL
			}
			return Issuer(config.PublicBaseURL, tenantID)
		}, nil
	}
	options := []op.Option{}
	if config.Insecure {
		options = append(options, op.WithAllowInsecure())
	}
	return op.NewProvider(providerConfig, storage, issuer, options...)
}

// tenantHandler adapts the provider to the tenant mount: it puts the tenant
// in the context (the library's storage interface carries no tenant), sets
// the issuer for URL building, and strips the tenant prefix so the library
// sees the paths it registered.
func tenantHandler(provider *op.Provider, publicBaseURL string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID, rest := splitTenantPath(r.URL.Path)
		if tenantID == "" {
			http.NotFound(w, r)
			return
		}
		ctx := internaloidc.WithTenant(r.Context(), tenantID)
		ctx = op.ContextWithIssuer(ctx, Issuer(publicBaseURL, tenantID))

		stripped := r.Clone(ctx)
		stripped.URL.Path = rest
		next.ServeHTTP(w, stripped)
	})
}

// splitTenantPath pulls the tenant out of /t/<tenantId>/<rest>.
func splitTenantPath(path string) (string, string) {
	if !strings.HasPrefix(path, TenantPathPrefix) {
		return "", ""
	}
	remainder := strings.TrimPrefix(path, TenantPathPrefix)
	tenantID, rest, found := strings.Cut(remainder, "/")
	if tenantID == "" {
		return "", ""
	}
	if !found {
		return tenantID, "/"
	}
	return tenantID, "/" + rest
}

// sessionCookie builds the single sign-on cookie. It is the IdP session, so
// it never leaves an's own origin and is unreadable to scripts.
func sessionCookie(name, value string, secure bool, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}
