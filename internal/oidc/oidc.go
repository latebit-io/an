package oidc

import (
	"context"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// tenantKey carries the tenant through the request context. The library's
// storage interface has no tenant parameter, so the mount puts it here and
// every storage method reads it back.
type tenantKey struct{}

// WithTenant returns a context carrying the tenant the OIDC request is for.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenantID)
}

// TenantFrom resolves the tenant a storage call operates on. A missing
// tenant is a wiring bug, never a default.
func TenantFrom(ctx context.Context) (string, error) {
	tenantID, ok := ctx.Value(tenantKey{}).(string)
	if !ok || tenantID == "" {
		return "", MissingTenantError{}
	}
	return tenantID, nil
}

// AuthRequest is one authorization request, live from /authorize until the
// code is exchanged. It implements op.AuthRequest: the library reads it
// through that interface, and it persists here as ordinary columns.
type AuthRequest struct {
	ID       string
	TenantID string
	ClientID string
	// Subject is the account id, empty until the login UI authenticates
	// the user. Sub is the account id, never the email.
	Subject             string
	RedirectURI         string
	ResponseType        string
	ResponseMode        string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AMR                 []string
	AuthTime            time.Time
	Complete            bool
	Expires             time.Time
	Created             time.Time
	Modified            time.Time
}

func (a *AuthRequest) GetID() string          { return a.ID }
func (a *AuthRequest) GetACR() string         { return "" }
func (a *AuthRequest) GetAMR() []string       { return a.AMR }
func (a *AuthRequest) GetAudience() []string  { return []string{a.ClientID} }
func (a *AuthRequest) GetAuthTime() time.Time { return a.AuthTime }
func (a *AuthRequest) GetClientID() string    { return a.ClientID }
func (a *AuthRequest) GetNonce() string       { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string { return a.RedirectURI }
func (a *AuthRequest) GetScopes() []string    { return a.Scopes }
func (a *AuthRequest) GetState() string       { return a.State }
func (a *AuthRequest) GetSubject() string     { return a.Subject }
func (a *AuthRequest) Done() bool             { return a.Complete }

func (a *AuthRequest) GetResponseType() oidc.ResponseType {
	return oidc.ResponseType(a.ResponseType)
}

func (a *AuthRequest) GetResponseMode() oidc.ResponseMode {
	return oidc.ResponseMode(a.ResponseMode)
}

// GetCodeChallenge returns nil when the client sent no PKCE challenge, which
// is how the library tells "no PKCE" from "PKCE that must verify".
func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.CodeChallenge,
		Method:    oidc.CodeChallengeMethod(a.CodeChallengeMethod),
	}
}

// RefreshToken is one issued grant. Unlike the api-key surface's sessions,
// which hold one row per (tenant, email, client), grants are one row each:
// the same account signed in from two browsers has two.
type RefreshToken struct {
	ID       string
	TenantID string
	ClientID string
	Subject  string
	Audience []string
	Scopes   []string
	AMR      []string
	AuthTime time.Time
	Expires  time.Time
	Created  time.Time
}

func (r *RefreshToken) GetAMR() []string       { return r.AMR }
func (r *RefreshToken) GetAudience() []string  { return r.Audience }
func (r *RefreshToken) GetAuthTime() time.Time { return r.AuthTime }
func (r *RefreshToken) GetClientID() string    { return r.ClientID }
func (r *RefreshToken) GetScopes() []string    { return r.Scopes }
func (r *RefreshToken) GetSubject() string     { return r.Subject }

func (r *RefreshToken) SetCurrentScopes(scopes []string) { r.Scopes = scopes }

// AccessToken is one issued opaque access token. Access tokens on this
// surface are not JWTs: the id is the credential (the library encrypts it
// before handing it out), so there is nothing to hash at rest.
type AccessToken struct {
	ID             string
	TenantID       string
	ClientID       string
	Subject        string
	Audience       []string
	Scopes         []string
	RefreshTokenID string
	Expires        time.Time
	Created        time.Time
}

// BrowserSession is the IdP session behind single sign-on: the cookie an
// sets at login so a second /authorize does not re-prompt.
type BrowserSession struct {
	ID        string
	TenantID  string
	AccountID string
	AuthTime  time.Time
	Expires   time.Time
	Created   time.Time
}
