package oidc

import (
	"context"
	"slices"
	"time"

	"github.com/latebit-io/an/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Scopes an issues. Anything else is refused rather than silently dropped.
const ScopeGroups = "groups"

// SupportedScopes and SupportedGrantTypes are the one statement of what
// this issuer accepts. Discovery advertises them and the client enforces
// them, so the document cannot promise what /authorize refuses.
var (
	SupportedScopes = []string{
		oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile, oidc.ScopeOfflineAccess, ScopeGroups,
	}
	SupportedGrantTypes = []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
)

// StaticClient is the single confidential client of the first cut. The
// client registry that replaces it is a later step; until then a client is
// configuration, not data.
//
// FirstParty is enforced, not decorative: consent is deferred on the
// understanding that these clients are first party, so a client that is not
// is refused rather than silently served without a consent screen.
type StaticClient struct {
	ID                     string
	SecretHash             string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	FirstParty             bool
	IDTokenLifetime        time.Duration
	ClockSkewTolerance     time.Duration
}

// ClientRegistry resolves client ids. One implementation today; the
// per-tenant registry slots in behind it.
type ClientRegistry interface {
	Client(ctx context.Context, tenantID, clientID string) (*StaticClient, error)
	Authenticate(ctx context.Context, tenantID, clientID, secret string) error
	// PostLogoutRedirect validates where logout may send a browser. An
	// unvalidated redirect target is an open redirect, which is worth
	// exactly as much to a phisher as it is to the client.
	PostLogoutRedirect(ctx context.Context, tenantID, clientID, redirectURI string) error
}

type StaticClientRegistry struct {
	client *StaticClient
}

func NewStaticClientRegistry(client *StaticClient) ClientRegistry {
	return &StaticClientRegistry{client: client}
}

func (r *StaticClientRegistry) Client(ctx context.Context, tenantID,
	clientID string) (*StaticClient, error) {
	if r.client == nil || r.client.ID != clientID {
		return nil, ClientNotFoundError{Value: clientID}
	}
	// Consent is deferred on the understanding that every client is first
	// party. A client that is not must fail here rather than quietly skip
	// a consent screen that does not exist yet.
	if !r.client.FirstParty {
		return nil, ClientNotFirstPartyError{Value: clientID}
	}
	return r.client, nil
}

// Authenticate compares the presented secret against the hash at rest. The
// secret is high entropy and configured, so sha256 matches the rule the
// rest of the service follows for such values.
func (r *StaticClientRegistry) Authenticate(ctx context.Context, tenantID, clientID,
	secret string) error {
	client, err := r.Client(ctx, tenantID, clientID)
	if err != nil {
		return err
	}
	if !utils.SafeCompare(utils.Sha256Hex(secret), client.SecretHash) {
		return ClientAuthenticationError{}
	}
	return nil
}

// PostLogoutRedirect admits only URIs the client registered. With no
// client id on the request the single configured client is used, which is
// sound while there is one; the registry step revisits it.
func (r *StaticClientRegistry) PostLogoutRedirect(ctx context.Context, tenantID, clientID,
	redirectURI string) error {
	client := r.client
	if clientID != "" {
		resolved, err := r.Client(ctx, tenantID, clientID)
		if err != nil {
			return err
		}
		client = resolved
	}
	if client == nil {
		return ClientNotFoundError{Value: clientID}
	}
	if !slices.Contains(client.PostLogoutRedirectURIs, redirectURI) {
		return RedirectURINotAllowedError{Value: redirectURI}
	}
	return nil
}

// providerClient adapts a StaticClient to op.Client. It exists so the
// library's interface never reaches beyond this package.
type providerClient struct {
	client *StaticClient
	// loginURL builds the login page URL for one authorization request,
	// already carrying the tenant prefix of the issuer it belongs to.
	loginURL func(authRequestID string) string
}

func (c *providerClient) GetID() string                        { return c.client.ID }
func (c *providerClient) RedirectURIs() []string               { return c.client.RedirectURIs }
func (c *providerClient) PostLogoutRedirectURIs() []string     { return c.client.PostLogoutRedirectURIs }
func (c *providerClient) ApplicationType() op.ApplicationType  { return op.ApplicationTypeWeb }
func (c *providerClient) AuthMethod() oidc.AuthMethod          { return oidc.AuthMethodBasic }
func (c *providerClient) LoginURL(id string) string            { return c.loginURL(id) }
func (c *providerClient) IDTokenLifetime() time.Duration       { return c.client.IDTokenLifetime }
func (c *providerClient) DevMode() bool                        { return false }
func (c *providerClient) ClockSkew() time.Duration             { return c.client.ClockSkewTolerance }
func (c *providerClient) IDTokenUserinfoClaimsAssertion() bool { return true }

// AccessTokenType is opaque by decision: the api-key surface's JWTs carry a
// single configured audience, which cannot express a per-client aud. Opaque
// tokens sidestep that entirely and make UserInfo a lookup.
func (c *providerClient) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeBearer
}

func (c *providerClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *providerClient) GrantTypes() []oidc.GrantType { return SupportedGrantTypes }

// IsScopeAllowed refuses anything outside the fixed set. Scope creep here
// would silently widen what an id_token asserts.
func (c *providerClient) IsScopeAllowed(scope string) bool {
	return slices.Contains(SupportedScopes, scope)
}

func (c *providerClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *providerClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
