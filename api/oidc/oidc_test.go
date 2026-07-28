package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/authn"
	internaloidc "github.com/latebit-io/an/internal/oidc"
	"github.com/latebit-io/an/internal/tokens"
	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestMain(m *testing.M) {
	os.Exit(utils.RunTestMain(m))
}

const (
	testTenant       = "default"
	testClientID     = "console"
	testClientSecret = "console-secret-value"
	testRedirectURI  = "http://127.0.0.1:1/callback"
	testEmail        = "user@example.com"
	testPassword     = "password-1"
	testName         = "Ada Lovelace"
)

// issuer is the provider under test, wired the way main.go wires it and
// served over a real HTTP server: no mocks, no in-process shortcuts.
type issuer struct {
	server         *httptest.Server
	pool           *pgxpool.Pool
	accounts       accounts.AccountService
	accountRepo    accounts.AccountRepository
	storage        *internaloidc.Storage
	authRequests   internaloidc.AuthRequestRepository
	tokenRepo      internaloidc.TokenRepository
	browserSession internaloidc.BrowserSessionRepository
	accountID      string
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	ctx := context.Background()
	pool := utils.NewTestPool(t)

	signingKeys := tokens.NewDefaultSigningKeyService(tokens.NewPostgresSigningKeyRepository(pool))
	require.NoError(t, signingKeys.Initialize(ctx))

	sessions := authn.NewPostgresSessionRepository(pool)
	attempts := authn.NewPostgresFailedAttemptRepository(pool)
	accountRepository := accounts.NewPostgresAccountRepository(pool)
	authRequests := internaloidc.NewPostgresAuthRequestRepository(pool)
	tokenRepository := internaloidc.NewPostgresTokenRepository(pool)
	browserSessions := internaloidc.NewPostgresBrowserSessionRepository(pool)
	accountService := accounts.NewDefaultAccountService(accountRepository,
		accounts.NewPostgresPasswordResetRepository(pool),
		[]accounts.SessionRevoker{sessions, internaloidc.NewSessionRevoker(browserSessions, tokenRepository)},
		attempts,
		utils.NewPostgresTxManager(pool), 4, time.Hour)
	tokenizer, err := tokens.NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, signingKeys)
	require.NoError(t, err)
	authentication := authn.NewDefaultAuthenticationService(accountRepository, sessions, attempts,
		tokenizer, 5, time.Hour)

	service := echo.New()
	// The server has to exist before the provider so the issuer URL is the
	// real one clients will verify against.
	server := httptest.NewUnstartedServer(service)
	baseURL := "http://" + server.Listener.Addr().String()

	registry := internaloidc.NewStaticClientRegistry(&internaloidc.StaticClient{
		ID:                     testClientID,
		SecretHash:             utils.Sha256Hex(testClientSecret),
		RedirectURIs:           []string{testRedirectURI},
		PostLogoutRedirectURIs: []string{testRedirectURI},
		FirstParty:             true,
		IDTokenLifetime:        time.Hour,
	})
	storage := internaloidc.NewStorage(authRequests, tokenRepository, accountRepository,
		signingKeys, registry,
		func(tenantID, authRequestID string) string {
			return LoginURL(baseURL, tenantID, authRequestID)
		}, 5*time.Minute, time.Hour, 24*time.Hour)

	provider, err := NewProvider(storage, ProviderConfig{
		PublicBaseURL: baseURL,
		CryptoKey:     sha256.Sum256([]byte("test-crypto-key")),
		Insecure:      true,
	})
	require.NoError(t, err)

	loginHandler, err := NewLoginHandler(storage, browserSessions, authentication,
		accountRepository, registry, provider, baseURL, false, 12*time.Hour)
	require.NoError(t, err)
	OidcRoutes(service, provider, loginHandler, baseURL)

	server.Start()
	t.Cleanup(server.Close)

	registered, err := accountService.Register(ctx, testTenant, testEmail, testPassword, testName)
	require.NoError(t, err)
	require.NoError(t, accountService.Verify(ctx, testTenant, testEmail,
		registered.VerificationToken))

	return &issuer{
		server:         server,
		pool:           pool,
		accounts:       accountService,
		accountRepo:    accountRepository,
		storage:        storage,
		authRequests:   authRequests,
		tokenRepo:      tokenRepository,
		browserSession: browserSessions,
		accountID:      registered.ID,
	}
}

func (i *issuer) url() string    { return "http://" + i.server.Listener.Addr().String() }
func (i *issuer) issuer() string { return Issuer(i.url(), testTenant) }

// relyingParty is a genuine OIDC client: go-oidc and x/oauth2 are already
// dependencies of an, so the test drives the flow with the same libraries
// an external consumer would, rather than hand-rolled HTTP.
type relyingParty struct {
	t        *testing.T
	provider *coreoidc.Provider
	config   oauth2.Config
	verifier *coreoidc.IDTokenVerifier
	client   *http.Client
}

// errStopAtRedirect halts the browser at the client's redirect URI, which
// is where a real browser would hand control back to the application.
var errStopAtRedirect = &url.Error{Op: "stop"}

func newRelyingParty(t *testing.T, i *issuer, scopes ...string) *relyingParty {
	t.Helper()
	ctx := context.Background()

	// Discovery: the client is told nothing but the issuer.
	provider, err := coreoidc.NewProvider(ctx, i.issuer())
	require.NoError(t, err)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), testRedirectURI) {
				return errStopAtRedirect
			}
			return nil
		},
	}
	return &relyingParty{
		t:        t,
		provider: provider,
		config: oauth2.Config{
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  testRedirectURI,
			Scopes:       append([]string{coreoidc.ScopeOpenID}, scopes...),
		},
		verifier: provider.Verifier(&coreoidc.Config{ClientID: testClientID}),
		client:   client,
	}
}

// authorize walks /authorize and the login form, returning the callback URL
// the client would receive.
func (rp *relyingParty) authorize(state, nonce, challenge string,
	credentials ...string) *url.URL {
	rp.t.Helper()
	options := []oauth2.AuthCodeOption{coreoidc.Nonce(nonce)}
	if challenge != "" {
		options = append(options, oauth2.S256ChallengeOption(challenge))
	}
	response := rp.get(rp.config.AuthCodeURL(state, options...))

	// A live single sign-on session skips the form entirely, which is what
	// makes the second application silent.
	if response.Request != nil && strings.HasPrefix(response.Request.URL.String(), testRedirectURI) {
		return response.Request.URL
	}
	body := readBody(rp.t, response)
	if !strings.Contains(body, "authRequestId") {
		rp.t.Fatalf("expected the login form, got: %s", body)
	}

	email, password := testEmail, testPassword
	if len(credentials) == 2 {
		email, password = credentials[0], credentials[1]
	}
	form := url.Values{
		"authRequestId": {field(rp.t, body, "authRequestId")},
		"csrf":          {field(rp.t, body, "csrf")},
		"email":         {email},
		"password":      {password},
	}
	posted, err := rp.client.PostForm(response.Request.URL.String(), form)
	if stopped(err) {
		return redirectURLFrom(err)
	}
	require.NoError(rp.t, err)
	defer posted.Body.Close()
	if posted.Request != nil && strings.HasPrefix(posted.Request.URL.String(), testRedirectURI) {
		return posted.Request.URL
	}
	rp.t.Fatalf("login did not reach the redirect uri: %d %s", posted.StatusCode,
		readBody(rp.t, posted))
	return nil
}

func (rp *relyingParty) get(target string) *http.Response {
	rp.t.Helper()
	response, err := rp.client.Get(target)
	if stopped(err) {
		return &http.Response{Request: &http.Request{URL: redirectURLFrom(err)}}
	}
	require.NoError(rp.t, err)
	return response
}

func stopped(err error) bool {
	urlErr, ok := err.(*url.Error)
	return ok && urlErr.Err == errStopAtRedirect
}

func redirectURLFrom(err error) *url.URL {
	parsed, _ := url.Parse(err.(*url.Error).URL)
	return parsed
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	if response.Body == nil {
		return ""
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return string(body)
}

// assertOpaque checks a token is encrypted rather than a readable signed
// JWT: the header must declare an encryption algorithm, and nothing in the
// token may be decodable as claims.
func assertOpaque(t *testing.T, token string) {
	t.Helper()
	segments := strings.Split(token, ".")
	require.Greater(t, len(segments), 1)
	rawHeader, err := base64.RawURLEncoding.DecodeString(segments[0])
	require.NoError(t, err)

	var header struct {
		Algorithm  string `json:"alg"`
		Encryption string `json:"enc"`
	}
	require.NoError(t, json.Unmarshal(rawHeader, &header))
	assert.NotEmpty(t, header.Encryption, "an access token must be encrypted, not signed")
	assert.NotEqual(t, "RS256", header.Algorithm)

	for _, segment := range segments[1:] {
		decoded, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			continue
		}
		var claims map[string]any
		if json.Unmarshal(decoded, &claims) == nil {
			assert.NotContains(t, claims, "sub", "no segment may expose claims")
		}
	}
}

var fieldPattern = regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`)

func field(t *testing.T, body, name string) string {
	t.Helper()
	for _, match := range fieldPattern.FindAllStringSubmatch(body, -1) {
		if match[1] == name {
			return match[2]
		}
	}
	t.Fatalf("no %s field in the login form", name)
	return ""
}

// The whole point of the surface: a browser signs in at /authorize, the
// client exchanges the code at /token, and the id_token verifies against
// the published JWKS carrying the four claims the first consumer requires.
func TestAuthorizationCodeFlow(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, coreoidc.ScopeOpenID, "email", "profile", "groups")

	verifier := oauth2.GenerateVerifier()
	callback := rp.authorize("state-1", "nonce-1", verifier)

	assert.Equal(t, "state-1", callback.Query().Get("state"), "state must round trip")
	code := callback.Query().Get("code")
	require.NotEmpty(t, code)

	token, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)

	rawIDToken, ok := token.Extra("id_token").(string)
	require.True(t, ok, "the response must carry an id_token")

	// Verified against the live JWKS by the same library an external
	// consumer would use.
	idToken, err := rp.verifier.Verify(ctx, rawIDToken)
	require.NoError(t, err)
	assert.Equal(t, i.issuer(), idToken.Issuer)
	assert.Equal(t, "nonce-1", idToken.Nonce)

	var claims struct {
		Subject       string   `json:"sub"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Name          string   `json:"name"`
		Groups        []string `json:"groups"`
	}
	require.NoError(t, idToken.Claims(&claims))

	// sub is the account id, never the email: relying parties key their
	// user tables on it and it must never be reassigned.
	assert.Equal(t, i.accountID, claims.Subject)
	assert.NotEqual(t, testEmail, claims.Subject)
	assert.Equal(t, testEmail, claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, testName, claims.Name)
	assert.NotNil(t, claims.Groups)
}

// The claims constraint is worth its own assertion: the first consumer
// reads all four from the id_token and never calls UserInfo, so a missing
// one fails opaquely downstream rather than loudly here.
func TestIDTokenCarriesAllRequiredClaims(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email", "profile", "groups")

	verifier := oauth2.GenerateVerifier()
	callback := rp.authorize("state-1", "nonce-1", verifier)
	token, err := rp.config.Exchange(ctx, callback.Query().Get("code"),
		oauth2.VerifierOption(verifier))
	require.NoError(t, err)

	idToken, err := rp.verifier.Verify(ctx, token.Extra("id_token").(string))
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, idToken.Claims(&claims))
	for _, claim := range []string{"sub", "email", "email_verified", "name", "groups"} {
		assert.Contains(t, claims, claim, "the id_token must carry %s", claim)
	}
}

// UserInfo is reached with the opaque access token and must agree with the
// id_token, since the two are shaped by one function.
func TestUserInfoAgreesWithIDToken(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email", "profile")

	verifier := oauth2.GenerateVerifier()
	callback := rp.authorize("state-1", "nonce-1", verifier)
	token, err := rp.config.Exchange(ctx, callback.Query().Get("code"),
		oauth2.VerifierOption(verifier))
	require.NoError(t, err)

	// Access tokens on this surface are opaque: encrypted, so the holder
	// can read nothing out of them, and in particular they are not signed
	// JWTs carrying claims with the single global audience.
	assertOpaque(t, token.AccessToken)
	_, err = rp.verifier.Verify(ctx, token.AccessToken)
	assert.Error(t, err, "an access token must not verify as an id_token")

	userinfo, err := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	require.NoError(t, err)
	assert.Equal(t, i.accountID, userinfo.Subject)
	assert.Equal(t, testEmail, userinfo.Email)
	assert.True(t, userinfo.EmailVerified)
}

// Discovery has to advertise the tenant issuer, or a relying party's issuer
// check fails at verification time rather than at configuration time.
func TestDiscoveryAdvertisesTenantIssuer(t *testing.T) {
	i := newIssuer(t)

	response, err := http.Get(i.issuer() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	body := readBody(t, response)
	assert.Contains(t, body, `"issuer":"`+i.issuer()+`"`)
	assert.Contains(t, body, i.issuer()+"/authorize")
	assert.Contains(t, body, i.issuer()+"/oauth/token")
	assert.Contains(t, body, i.issuer()+"/userinfo")
	assert.Contains(t, body, i.issuer()+"/keys")
	assert.Contains(t, body, i.issuer()+"/end_session")
}

// Single sign-on: a second client reaching /authorize with a live session
// must not re-prompt. Without this the cookie buys nothing.
func TestSecondAuthorizeIsSilent(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	first := oauth2.GenerateVerifier()
	callback := rp.authorize("state-1", "nonce-1", first)
	require.NotEmpty(t, callback.Query().Get("code"))

	// Same browser, new authorization request, no credentials submitted.
	second := oauth2.GenerateVerifier()
	response := rp.get(rp.config.AuthCodeURL("state-2",
		coreoidc.Nonce("nonce-2"), oauth2.S256ChallengeOption(second)))
	require.NotNil(t, response.Request)
	require.True(t, strings.HasPrefix(response.Request.URL.String(), testRedirectURI),
		"a live session must complete /authorize without the form")

	assert.Equal(t, "state-2", response.Request.URL.Query().Get("state"))
	token, err := rp.config.Exchange(ctx, response.Request.URL.Query().Get("code"),
		oauth2.VerifierOption(second))
	require.NoError(t, err)
	idToken, err := rp.verifier.Verify(ctx, token.Extra("id_token").(string))
	require.NoError(t, err)
	assert.Equal(t, "nonce-2", idToken.Nonce)
}

// Logout ends the single sign-on session, so the next /authorize prompts
// again. A session a user cannot end is the reason logout is in the first
// cut rather than deferred.
func TestLogoutEndsSingleSignOn(t *testing.T) {
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	rp.authorize("state-1", "nonce-1", oauth2.GenerateVerifier())

	response, err := rp.client.Get(i.issuer() + EndSessionPath)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	response.Body.Close()

	next := rp.get(rp.config.AuthCodeURL("state-2", coreoidc.Nonce("nonce-2"),
		oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	body := readBody(t, next)
	assert.Contains(t, body, "authRequestId", "after logout the form must be shown again")
}

// The refresh grant, which relying parties expect at /token. Rotation is a
// delete: the spent token cannot renew again.
func TestRefreshGrantRotates(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email", coreoidc.ScopeOfflineAccess)

	verifier := oauth2.GenerateVerifier()
	callback := rp.authorize("state-1", "nonce-1", verifier)
	token, err := rp.config.Exchange(ctx, callback.Query().Get("code"),
		oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	require.NotEmpty(t, token.RefreshToken, "offline_access must yield a refresh token")

	// Force a renewal by presenting an expired access token.
	stale := *token
	stale.Expiry = time.Now().Add(-time.Hour)
	renewed, err := rp.config.TokenSource(ctx, &stale).Token()
	require.NoError(t, err)
	assert.NotEqual(t, token.AccessToken, renewed.AccessToken)
	assert.NotEqual(t, token.RefreshToken, renewed.RefreshToken, "the refresh token must rotate")

	// The spent refresh token is dead.
	spent := *token
	spent.Expiry = time.Now().Add(-time.Hour)
	_, err = rp.config.TokenSource(ctx, &spent).Token()
	assert.Error(t, err, "a rotated-away refresh token must not renew")
}

// The failure paths are the security-relevant ones, so they get explicit
// tests rather than a manual check.

// An authorization code is single-use: the token endpoint deletes the
// request on a successful exchange, so a replay finds nothing.
func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	verifier := oauth2.GenerateVerifier()
	code := rp.authorize("state-1", "nonce-1", verifier).Query().Get("code")

	_, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	require.NoError(t, err)

	_, err = rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	assert.Error(t, err, "a replayed authorization code must not exchange")
}

// PKCE has to actually verify, or it is decoration.
func TestPKCEVerifierMismatchIsRejected(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	code := rp.authorize("state-1", "nonce-1", oauth2.GenerateVerifier()).Query().Get("code")

	_, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(oauth2.GenerateVerifier()))
	assert.Error(t, err, "a mismatched code verifier must not exchange")
}

// The redirect URI is matched exactly. A client that registered one URI
// cannot be talked into sending the code somewhere else.
func TestUnregisteredRedirectURIIsRejected(t *testing.T) {
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	hostile := rp.config
	hostile.RedirectURL = "http://attacker.example.com/callback"
	response, err := rp.client.Get(hostile.AuthCodeURL("state-1"))
	require.NoError(t, err)
	defer response.Body.Close()

	assert.NotEqual(t, http.StatusFound, response.StatusCode)
	assert.NotContains(t, readBody(t, response), "authRequestId",
		"an unregistered redirect uri must not reach the login form")
}

// The token endpoint authenticates the client. Holding a code is not
// enough.
func TestWrongClientSecretIsRejected(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	verifier := oauth2.GenerateVerifier()
	code := rp.authorize("state-1", "nonce-1", verifier).Query().Get("code")

	impostor := rp.config
	impostor.ClientSecret = "wrong-secret"
	_, err := impostor.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	assert.Error(t, err, "the token endpoint must authenticate the client")
}

// An unknown client never gets as far as a login form.
func TestUnknownClientIsRejected(t *testing.T) {
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	stranger := rp.config
	stranger.ClientID = "not-registered"
	response, err := rp.client.Get(stranger.AuthCodeURL("state-1"))
	require.NoError(t, err)
	defer response.Body.Close()
	assert.NotContains(t, readBody(t, response), "authRequestId")
}

// state is the client's CSRF defence and must round trip untouched. A
// tampered value has to reach the client unchanged so the client can catch
// it: the issuer echoes what it was given, and the mismatch is detectable.
func TestStateRoundTripsUnmodified(t *testing.T) {
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	callback := rp.authorize("state-with-\"quotes\"-and-&-ampersands", "nonce-1",
		oauth2.GenerateVerifier())
	assert.Equal(t, "state-with-\"quotes\"-and-&-ampersands", callback.Query().Get("state"))
}

// The nonce binds the id_token to one authorization request. A client
// verifying a different nonce must reject the token.
func TestNonceBindsTheIDToken(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	verifier := oauth2.GenerateVerifier()
	callback := rp.authorize("state-1", "nonce-1", verifier)
	token, err := rp.config.Exchange(ctx, callback.Query().Get("code"),
		oauth2.VerifierOption(verifier))
	require.NoError(t, err)

	idToken, err := rp.verifier.Verify(ctx, token.Extra("id_token").(string))
	require.NoError(t, err)
	assert.Equal(t, "nonce-1", idToken.Nonce)
	assert.NotEqual(t, "nonce-2", idToken.Nonce)
}

// An expired authorization request is gone, whether or not the janitor has
// swept it: expiry is enforced on read.
func TestExpiredAuthRequestIsRejected(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	verifier := oauth2.GenerateVerifier()
	code := rp.authorize("state-1", "nonce-1", verifier).Query().Get("code")

	_, err := i.pool.Exec(ctx, "UPDATE oidc_auth_requests SET expires = now() - interval '1 minute'")
	require.NoError(t, err)

	_, err = rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	assert.Error(t, err, "an expired authorization request must not exchange")
}

// The login form is CSRF protected: a POST without the matching cookie
// token is refused even with correct credentials.
func TestLoginRequiresCSRFToken(t *testing.T) {
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	response := rp.get(rp.config.AuthCodeURL("state-1",
		oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	body := readBody(t, response)
	loginURL := response.Request.URL.String()

	// A fresh client has the form but not the cookie.
	naked := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	posted, err := naked.PostForm(loginURL, url.Values{
		"authRequestId": {field(t, body, "authRequestId")},
		"csrf":          {field(t, body, "csrf")},
		"email":         {testEmail},
		"password":      {testPassword},
	})
	require.NoError(t, err)
	defer posted.Body.Close()
	assert.Equal(t, http.StatusBadRequest, posted.StatusCode)
}

// A wrong password must not reveal whether the account exists, and neither
// must an unknown one. Both render the same message.
func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	i := newIssuer(t)

	wrongPassword := newRelyingParty(t, i, "email")
	wrongPasswordBody := wrongPassword.submitAndRead(t, "state-1", testEmail, "wrong-password")

	unknownAccount := newRelyingParty(t, i, "email")
	unknownBody := unknownAccount.submitAndRead(t, "state-1", "nobody@example.com", "wrong-password")

	assert.Contains(t, wrongPasswordBody, "Incorrect email or password.")
	assert.Contains(t, unknownBody, "Incorrect email or password.")
}

// A code presented to another tenant's token endpoint does not exchange.
// Note this passes even with an's tenant check removed: the library
// rejects it first with "invalid code". The tenant check itself is what
// TestCrossTenantReadsAreRejected in internal/oidc covers, where it can
// actually fail.
func TestCrossTenantCodeIsRejected(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	verifier := oauth2.GenerateVerifier()
	code := rp.authorize("state-1", "nonce-1", verifier).Query().Get("code")

	// Same code, another tenant's token endpoint.
	other := rp.config
	other.Endpoint.TokenURL = strings.Replace(other.Endpoint.TokenURL,
		"/t/"+testTenant+"/", "/t/other/", 1)
	_, err := other.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	assert.Error(t, err, "a code must not exchange under another tenant")
}

// submitAndRead runs /authorize and posts the given credentials, returning
// the rendered page.
func (rp *relyingParty) submitAndRead(t *testing.T, state, email, password string) string {
	t.Helper()
	response := rp.get(rp.config.AuthCodeURL(state,
		oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	body := readBody(t, response)

	posted, err := rp.client.PostForm(response.Request.URL.String(), url.Values{
		"authRequestId": {field(t, body, "authRequestId")},
		"csrf":          {field(t, body, "csrf")},
		"email":         {email},
		"password":      {password},
	})
	require.NoError(t, err)
	defer posted.Body.Close()
	return readBody(t, posted)
}

// Discovery must not advertise what this issuer cannot do. The library
// hardcodes its response type list and claims jwt-bearer support
// unconditionally, so a client reading the raw document would be told it
// can use the implicit flow, the jwt-bearer grant or the device flow, and
// would then be refused at request time.
func TestDiscoveryDoesNotOverAdvertise(t *testing.T) {
	i := newIssuer(t)

	response, err := http.Get(i.issuer() + DiscoveryPath)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	var document map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&document))

	assert.Equal(t, []any{"code"}, document["response_types_supported"],
		"only the code flow is offered")
	assert.ElementsMatch(t, []any{"authorization_code", "refresh_token"},
		document["grant_types_supported"])
	assert.NotContains(t, document, "device_authorization_endpoint",
		"the device flow has no backing storage here")

	// What remains still has to be the truth, and still has to come from
	// the library rather than a hand-written copy.
	assert.Equal(t, i.issuer(), document["issuer"])
	assert.Equal(t, i.issuer()+"/oauth/token", document["token_endpoint"])
	assert.Contains(t, document, "userinfo_endpoint")
	assert.Contains(t, document, "end_session_endpoint")
	assert.Contains(t, document, "jwks_uri")
}

// Everything discovery still advertises must actually work, which is the
// half that keeps the pruning honest as the surface changes.
func TestAdvertisedCapabilitiesWork(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email", coreoidc.ScopeOfflineAccess)

	response, err := http.Get(i.issuer() + DiscoveryPath)
	require.NoError(t, err)
	defer response.Body.Close()
	var document map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&document))

	// authorization_code
	verifier := oauth2.GenerateVerifier()
	callback := rp.authorize("state-1", "nonce-1", verifier)
	token, err := rp.config.Exchange(ctx, callback.Query().Get("code"),
		oauth2.VerifierOption(verifier))
	require.NoError(t, err, "the advertised authorization_code grant must work")

	// refresh_token
	stale := *token
	stale.Expiry = time.Now().Add(-time.Hour)
	_, err = rp.config.TokenSource(ctx, &stale).Token()
	require.NoError(t, err, "the advertised refresh_token grant must work")

	// Every advertised endpoint answers rather than 404s.
	for _, field := range []string{"userinfo_endpoint", "jwks_uri", "end_session_endpoint"} {
		endpoint, ok := document[field].(string)
		require.True(t, ok, "%s must be advertised", field)
		probe, err := http.Get(endpoint)
		require.NoError(t, err)
		probe.Body.Close()
		assert.NotEqual(t, http.StatusNotFound, probe.StatusCode,
			"%s is advertised but not mounted", field)
	}
}

// Logout may only send a browser where the client registered. An
// unvalidated post_logout_redirect_uri is an open redirect, and one that
// starts at the identity provider is worth more to a phisher than most.
func TestLogoutRefusesUnregisteredRedirect(t *testing.T) {
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")
	rp.authorize("state-1", "nonce-1", oauth2.GenerateVerifier())

	hostile, err := rp.client.Get(i.issuer() + EndSessionPath +
		"?post_logout_redirect_uri=http%3A%2F%2Fattacker.example.com%2F")
	require.NoError(t, err)
	defer hostile.Body.Close()
	assert.Equal(t, http.StatusBadRequest, hostile.StatusCode,
		"logout must not redirect to an unregistered uri")

	// The registered one is honoured, and state round trips with it.
	stopAtRedirect := &http.Client{
		Jar: rp.client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	allowed, err := stopAtRedirect.Get(i.issuer() + EndSessionPath +
		"?post_logout_redirect_uri=" + url.QueryEscape(testRedirectURI) + "&state=bye")
	require.NoError(t, err)
	defer allowed.Body.Close()
	require.Equal(t, http.StatusFound, allowed.StatusCode)

	location, err := url.Parse(allowed.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "bye", location.Query().Get("state"))
}

// Every endpoint discovery advertises must also be exempt from the api key
// gate. Advertising an endpoint that answers 401 to a relying party is the
// same failure as advertising one that 404s, and checking a hand-listed few
// is how the introspection endpoint was missed: this walks the document
// instead.
func TestEveryAdvertisedEndpointIsPublic(t *testing.T) {
	i := newIssuer(t)

	response, err := http.Get(i.issuer() + DiscoveryPath)
	require.NoError(t, err)
	defer response.Body.Close()
	var document map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&document))

	advertised := 0
	for field, value := range document {
		if !strings.HasSuffix(field, "_endpoint") && field != "jwks_uri" {
			continue
		}
		endpoint, ok := value.(string)
		if !ok || endpoint == "" {
			continue
		}
		parsed, err := url.Parse(endpoint)
		require.NoError(t, err)
		assert.True(t, IsProviderPath(parsed.Path),
			"%s (%s) is advertised but the api key gate would refuse it", field, parsed.Path)
		advertised++
	}
	require.Greater(t, advertised, 4, "the document should advertise several endpoints")

	// The paths an serves itself are public too.
	for _, path := range []string{DiscoveryPath, LoginPath, LogoutPath, "/authorize/callback"} {
		assert.True(t, IsProviderPath(TenantPathPrefix+testTenant+path), "%s must be public", path)
	}
}

// A credential change has to end sessions on every surface. Until it did,
// changing a password left the single sign-on cookie live and every issued
// grant usable: the user believes they have locked an attacker out, and
// they have not.
func TestPasswordChangeEndsSingleSignOnAndGrants(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email", coreoidc.ScopeOfflineAccess)

	verifier := oauth2.GenerateVerifier()
	callback := rp.authorize("state-1", "nonce-1", verifier)
	token, err := rp.config.Exchange(ctx, callback.Query().Get("code"),
		oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	require.NotEmpty(t, token.RefreshToken)

	// The browser is signed in: a second authorization is silent.
	silent := rp.get(rp.config.AuthCodeURL("state-2", coreoidc.Nonce("nonce-2"),
		oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	require.True(t, strings.HasPrefix(silent.Request.URL.String(), testRedirectURI),
		"precondition: the session is live before the password changes")

	require.NoError(t, i.accounts.UpdatePassword(ctx, testTenant, testEmail, testPassword,
		"a-brand-new-password"))

	// The single sign-on session is gone, so /authorize prompts again.
	after := rp.get(rp.config.AuthCodeURL("state-3", coreoidc.Nonce("nonce-3"),
		oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	assert.Contains(t, readBody(t, after), "authRequestId",
		"the password changed, so the browser must sign in again")

	// The refresh token issued under the old password is dead.
	stale := *token
	stale.Expiry = time.Now().Add(-time.Hour)
	_, err = rp.config.TokenSource(ctx, &stale).Token()
	assert.Error(t, err, "a grant issued under the old password must not renew")
}

// A reset does the same, by the same seam.
func TestPasswordResetEndsSingleSignOn(t *testing.T) {
	ctx := context.Background()
	i := newIssuer(t)
	rp := newRelyingParty(t, i, "email")

	rp.authorize("state-1", "nonce-1", oauth2.GenerateVerifier())

	reset, err := i.accounts.Forgot(ctx, testTenant, testEmail)
	require.NoError(t, err)
	require.NoError(t, i.accounts.Reset(ctx, testTenant, testEmail, reset.Token, "another-password"))

	after := rp.get(rp.config.AuthCodeURL("state-2", coreoidc.Nonce("nonce-2"),
		oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	assert.Contains(t, readBody(t, after), "authRequestId")
}
