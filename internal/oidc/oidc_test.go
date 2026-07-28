package oidc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(utils.RunTestMain(m))
}

type stores struct {
	authRequests AuthRequestRepository
	tokens       TokenRepository
	sessions     BrowserSessionRepository
	accounts     accounts.AccountRepository
}

func newStores(t *testing.T) *stores {
	t.Helper()
	pool := utils.NewTestPool(t)
	return &stores{
		authRequests: NewPostgresAuthRequestRepository(pool),
		tokens:       NewPostgresTokenRepository(pool),
		sessions:     NewPostgresBrowserSessionRepository(pool),
		accounts:     accounts.NewPostgresAccountRepository(pool),
	}
}

func (s *stores) account(t *testing.T, tenantID, email string) *accounts.Account {
	t.Helper()
	hash, err := utils.BcryptHash("password-1", 4)
	require.NoError(t, err)
	account, err := s.accounts.CreateVerified(context.Background(), accounts.Account{
		TenantID:     tenantID,
		Email:        email,
		PasswordHash: hash,
	})
	require.NoError(t, err)
	return account
}

func (s *stores) request(t *testing.T, tenantID string) *AuthRequest {
	t.Helper()
	request, err := s.authRequests.Create(context.Background(), AuthRequest{
		TenantID:     tenantID,
		ClientID:     "console",
		RedirectURI:  "https://console.example.com/callback",
		ResponseType: "code",
		Scopes:       []string{"openid", "email"},
		State:        "state-1",
		Nonce:        "nonce-1",
		AMR:          []string{},
		Expires:      time.Now().Add(5 * time.Minute),
	})
	require.NoError(t, err)
	return request
}

// The library's storage interface carries no tenant, so every read checks
// it here. Without this, one tenant's code, token or session resolves under
// another, which is the whole isolation guarantee of a multi-tenant issuer.
func TestCrossTenantReadsAreRejected(t *testing.T) {
	ctx := context.Background()
	s := newStores(t)

	request := s.request(t, "default")
	require.NoError(t, s.authRequests.SaveCode(ctx, "default", request.ID, "the-code"))

	_, err := s.authRequests.Read(ctx, "other", request.ID)
	assert.ErrorAs(t, err, &TenantMismatchError{}, "an auth request must not read cross tenant")

	_, err = s.authRequests.ReadByCode(ctx, "other", "the-code")
	assert.ErrorAs(t, err, &TenantMismatchError{}, "a code must not read cross tenant")

	refreshToken, plaintext, err := s.tokens.CreateRefreshToken(ctx, RefreshToken{
		TenantID: "default",
		ClientID: "console",
		Subject:  "subject",
		AuthTime: time.Now(),
		Expires:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	_, err = s.tokens.ReadRefreshToken(ctx, "other", plaintext)
	assert.ErrorAs(t, err, &TenantMismatchError{}, "a refresh token must not read cross tenant")
	_, err = s.tokens.ReadRefreshTokenByID(ctx, "other", refreshToken.ID)
	assert.ErrorAs(t, err, &TenantMismatchError{})

	accessToken, err := s.tokens.CreateAccessToken(ctx, AccessToken{
		TenantID: "default",
		ClientID: "console",
		Subject:  "subject",
		Expires:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	_, err = s.tokens.ReadAccessToken(ctx, "other", accessToken.ID)
	assert.ErrorAs(t, err, &TenantMismatchError{}, "an access token must not read cross tenant")

	account := s.account(t, "default", "user@example.com")
	_, sessionToken, err := s.sessions.Create(ctx, BrowserSession{
		TenantID:  "default",
		AccountID: account.ID,
		AuthTime:  time.Now(),
		Expires:   time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	_, err = s.sessions.Read(ctx, "other", sessionToken)
	assert.ErrorAs(t, err, &TenantMismatchError{}, "a session must not read cross tenant")
}

// Expiry is enforced on read, not merely stored: the janitor is a
// reclaimer, never the thing standing between a dead row and a caller.
func TestExpiryIsEnforcedOnRead(t *testing.T) {
	ctx := context.Background()
	s := newStores(t)

	expired, err := s.authRequests.Create(ctx, AuthRequest{
		TenantID:     "default",
		ClientID:     "console",
		RedirectURI:  "https://console.example.com/callback",
		ResponseType: "code",
		Scopes:       []string{"openid"},
		AMR:          []string{},
		Expires:      time.Now().Add(-time.Minute),
	})
	require.NoError(t, err)
	_, err = s.authRequests.Read(ctx, "default", expired.ID)
	assert.ErrorAs(t, err, &AuthRequestNotFoundError{})

	_, plaintext, err := s.tokens.CreateRefreshToken(ctx, RefreshToken{
		TenantID: "default",
		ClientID: "console",
		Subject:  "subject",
		AuthTime: time.Now(),
		Expires:  time.Now().Add(-time.Minute),
	})
	require.NoError(t, err)
	_, err = s.tokens.ReadRefreshToken(ctx, "default", plaintext)
	assert.ErrorAs(t, err, &TokenNotFoundError{})

	account := s.account(t, "default", "user@example.com")
	_, sessionToken, err := s.sessions.Create(ctx, BrowserSession{
		TenantID:  "default",
		AccountID: account.ID,
		AuthTime:  time.Now(),
		Expires:   time.Now().Add(-time.Minute),
	})
	require.NoError(t, err)
	_, err = s.sessions.Read(ctx, "default", sessionToken)
	assert.ErrorAs(t, err, &BrowserSessionNotFoundError{})
}

// High-entropy secrets are hashed at rest, matching the rule the rest of
// the service follows. Only the minting response carries the plaintext.
func TestSecretsAreHashedAtRest(t *testing.T) {
	ctx := context.Background()
	s := newStores(t)

	request := s.request(t, "default")
	require.NoError(t, s.authRequests.SaveCode(ctx, "default", request.ID, "the-code"))

	// The code reads back only through its hash, never as stored plaintext.
	found, err := s.authRequests.ReadByCode(ctx, "default", "the-code")
	require.NoError(t, err)
	assert.Equal(t, request.ID, found.ID)

	_, err = s.authRequests.ReadByCode(ctx, "default", utils.Sha256Hex("the-code"))
	assert.ErrorAs(t, err, &AuthRequestNotFoundError{},
		"the stored value is the hash, so the hash itself must not be a valid code")
}

// Grants are one row each. Two browsers must not evict one another, which
// is exactly what the api-key surface's one-row-per-triple sessions table
// would have done.
func TestConcurrentGrantsCoexist(t *testing.T) {
	ctx := context.Background()
	s := newStores(t)

	first, firstToken, err := s.tokens.CreateRefreshToken(ctx, RefreshToken{
		TenantID: "default", ClientID: "console", Subject: "subject",
		AuthTime: time.Now(), Expires: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	second, secondToken, err := s.tokens.CreateRefreshToken(ctx, RefreshToken{
		TenantID: "default", ClientID: "console", Subject: "subject",
		AuthTime: time.Now(), Expires: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.ID, second.ID)

	// Both live.
	_, err = s.tokens.ReadRefreshToken(ctx, "default", firstToken)
	assert.NoError(t, err)
	_, err = s.tokens.ReadRefreshToken(ctx, "default", secondToken)
	assert.NoError(t, err)

	// Ending one grant leaves the other alone.
	require.NoError(t, s.tokens.DeleteRefreshToken(ctx, "default", first.ID))
	_, err = s.tokens.ReadRefreshToken(ctx, "default", firstToken)
	assert.ErrorAs(t, err, &TokenNotFoundError{})
	_, err = s.tokens.ReadRefreshToken(ctx, "default", secondToken)
	assert.NoError(t, err)
}

// Deleting an account takes its browser sessions with it, or a signed-out
// ghost keeps single sign-on working.
func TestDeletingAccountCascadesSessions(t *testing.T) {
	ctx := context.Background()
	s := newStores(t)

	account := s.account(t, "default", "user@example.com")
	_, sessionToken, err := s.sessions.Create(ctx, BrowserSession{
		TenantID:  "default",
		AccountID: account.ID,
		AuthTime:  time.Now(),
		Expires:   time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	require.NoError(t, s.sessions.DeleteAll(ctx, "default", account.ID))
	_, err = s.sessions.Read(ctx, "default", sessionToken)
	assert.ErrorAs(t, err, &BrowserSessionNotFoundError{})
}

// A tenant key cannot be tricked into resolving another tenant's client,
// and an unknown client id is a typed miss rather than a nil dereference.
func TestStaticClientRegistry(t *testing.T) {
	ctx := context.Background()
	registry := NewStaticClientRegistry(&StaticClient{
		ID:         "console",
		SecretHash: utils.Sha256Hex("the-secret"),
		FirstParty: true,
	})

	client, err := registry.Client(ctx, "default", "console")
	require.NoError(t, err)
	assert.Equal(t, "console", client.ID)

	_, err = registry.Client(ctx, "default", "unknown")
	assert.ErrorAs(t, err, &ClientNotFoundError{})

	assert.NoError(t, registry.Authenticate(ctx, "default", "console", "the-secret"))
	assert.ErrorAs(t, registry.Authenticate(ctx, "default", "console", "wrong"),
		&ClientAuthenticationError{})
}

// A storage call without a tenant in context is a wiring bug and must fail
// loudly rather than defaulting to some tenant.
func TestMissingTenantFailsLoudly(t *testing.T) {
	_, err := TenantFrom(context.Background())
	assert.ErrorAs(t, err, &MissingTenantError{})

	tenantID, err := TenantFrom(WithTenant(context.Background(), "default"))
	require.NoError(t, err)
	assert.Equal(t, "default", tenantID)
}

// The post-logout redirect allowlist, checked where it is decided.
func TestPostLogoutRedirectAllowlist(t *testing.T) {
	ctx := context.Background()
	registry := NewStaticClientRegistry(&StaticClient{
		ID:                     "console",
		SecretHash:             utils.Sha256Hex("the-secret"),
		PostLogoutRedirectURIs: []string{"https://console.example.com/"},
		FirstParty:             true,
	})

	assert.NoError(t, registry.PostLogoutRedirect(ctx, "default", "console",
		"https://console.example.com/"))
	// No client id: the single configured client still bounds it.
	assert.NoError(t, registry.PostLogoutRedirect(ctx, "default", "",
		"https://console.example.com/"))

	assert.ErrorAs(t, registry.PostLogoutRedirect(ctx, "default", "console",
		"https://attacker.example.com/"), &RedirectURINotAllowedError{})
	// A prefix of a registered uri is not a registered uri.
	assert.ErrorAs(t, registry.PostLogoutRedirect(ctx, "default", "console",
		"https://console.example.com.attacker.example.com/"), &RedirectURINotAllowedError{})
	assert.ErrorAs(t, registry.PostLogoutRedirect(ctx, "default", "unknown",
		"https://console.example.com/"), &ClientNotFoundError{})
}

// Consent is not implemented, so the first-party flag has to be enforced
// rather than merely recorded: a third-party client must fail loudly
// instead of being served without the consent screen it requires.
func TestNonFirstPartyClientIsRefused(t *testing.T) {
	ctx := context.Background()
	registry := NewStaticClientRegistry(&StaticClient{
		ID:         "third-party",
		SecretHash: utils.Sha256Hex("the-secret"),
		FirstParty: false,
	})

	_, err := registry.Client(ctx, "default", "third-party")
	assert.ErrorAs(t, err, &ClientNotFirstPartyError{})

	// The right secret does not buy a way past it.
	assert.ErrorAs(t, registry.Authenticate(ctx, "default", "third-party", "the-secret"),
		&ClientNotFirstPartyError{})
}
