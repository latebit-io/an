package oidc

import (
	"context"
	"crypto/rsa"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/tokens"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// The provider library only ever sees an through these two interfaces.
var (
	_ op.Storage                   = (*Storage)(nil)
	_ op.CanSetUserinfoFromRequest = (*Storage)(nil)
)

// Storage implements op.Storage. It is the only place the provider library
// reaches into an, and the only place an imports it.
type Storage struct {
	authRequests   AuthRequestRepository
	tokens         TokenRepository
	accounts       accounts.AccountRepository
	signingKeys    tokens.SigningKeyService
	clients        ClientRegistry
	loginURL       func(tenantID, authRequestID string) string
	authCodeExpiry time.Duration
	accessExpiry   time.Duration
	refreshExpiry  time.Duration

	// keys caches the parsed signing keys. The library asks for the
	// signing key on every token response and for the key set on every
	// JWKS fetch, and parsing an RSA private key runs Precompute and
	// Validate. ReloadKeys swaps them, as DefaultTokenizer does.
	keys       sync.RWMutex
	signingKey op.SigningKey
	keySet     []op.Key
}

func NewStorage(authRequests AuthRequestRepository, tokenRepository TokenRepository,
	accountRepository accounts.AccountRepository, signingKeys tokens.SigningKeyService,
	clients ClientRegistry, loginURL func(tenantID, authRequestID string) string,
	authCodeExpiry, accessExpiry, refreshExpiry time.Duration) *Storage {
	return &Storage{
		authRequests:   authRequests,
		tokens:         tokenRepository,
		accounts:       accountRepository,
		signingKeys:    signingKeys,
		clients:        clients,
		loginURL:       loginURL,
		authCodeExpiry: authCodeExpiry,
		accessExpiry:   accessExpiry,
		refreshExpiry:  refreshExpiry,
	}
}

// ReloadKeys re-reads and re-parses the signing keys, so a rotation takes
// effect without a restart. Called at startup and from the janitor.
func (s *Storage) ReloadKeys(ctx context.Context) error {
	signingKeys, err := s.signingKeys.Keys(ctx)
	if err != nil {
		return err
	}
	if len(signingKeys) == 0 {
		return tokens.NoSigningKeyError{}
	}
	keySet := make([]op.Key, 0, len(signingKeys))
	for _, key := range signingKeys {
		publicKey, err := tokens.ParsePublicKey(key.PublicKeyPEM)
		if err != nil {
			return err
		}
		keySet = append(keySet, &publicKeyEntry{kid: key.Kid, key: publicKey})
	}
	latest := signingKeys[len(signingKeys)-1]
	privateKey, err := tokens.ParsePrivateKey(latest.PrivateKeyPEM)
	if err != nil {
		return err
	}

	s.keys.Lock()
	defer s.keys.Unlock()
	s.signingKey = &signingKey{kid: latest.Kid, key: privateKey}
	s.keySet = keySet
	return nil
}

// Health backs the library's readiness check.
func (s *Storage) Health(ctx context.Context) error {
	return nil
}

// CreateAuthRequest stores the /authorize request. The subject stays empty
// until the login UI authenticates the user.
func (s *Storage) CreateAuthRequest(ctx context.Context, request *oidc.AuthRequest,
	_ string) (op.AuthRequest, error) {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	stored := AuthRequest{
		TenantID:     tenantID,
		ClientID:     request.ClientID,
		RedirectURI:  request.RedirectURI,
		ResponseType: string(request.ResponseType),
		ResponseMode: string(request.ResponseMode),
		Scopes:       request.Scopes,
		State:        request.State,
		Nonce:        request.Nonce,
		AMR:          []string{},
		Expires:      time.Now().Add(s.authCodeExpiry),
	}
	if request.CodeChallenge != "" {
		stored.CodeChallenge = request.CodeChallenge
		stored.CodeChallengeMethod = string(request.CodeChallengeMethod)
	}
	created, err := s.authRequests.Create(ctx, stored)
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	request, err := s.authRequests.Read(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return request, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	request, err := s.authRequests.ReadByCode(ctx, tenantID, code)
	if err != nil {
		return nil, err
	}
	return request, nil
}

func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	return s.authRequests.SaveCode(ctx, tenantID, id, code)
}

// DeleteAuthRequest is what makes an authorization code single-use: the
// token endpoint calls it after a successful exchange, so a replay of the
// same code finds nothing.
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	err = s.authRequests.Delete(ctx, tenantID, id)
	// A request already gone is the desired end state, not a failure.
	if errors.As(err, &AuthRequestNotFoundError{}) {
		return nil
	}
	return err
}

// AuthenticateRequest completes an authorization request once the login UI
// has verified the user. Subject is the account id.
func (s *Storage) AuthenticateRequest(ctx context.Context, id, subject string,
	authTime time.Time, amr []string) error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	return s.authRequests.Authenticate(ctx, tenantID, id, subject, authTime, amr)
}

func (s *Storage) CreateAccessToken(ctx context.Context,
	request op.TokenRequest) (string, time.Time, error) {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	token, err := s.createAccessToken(ctx, tenantID, request, "")
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, token.Expires, nil
}

// CreateAccessAndRefreshTokens mints a pair, rotating the presented refresh
// token when this is a renewal. Rotation is a delete: the old token cannot
// renew again.
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest,
	currentRefreshToken string) (string, string, time.Time, error) {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if currentRefreshToken != "" {
		// The library loaded this row already and passes it back as the
		// request, so rotation costs a delete rather than another read.
		spent, ok := request.(*RefreshToken)
		if !ok {
			var err error
			spent, err = s.tokens.ReadRefreshToken(ctx, tenantID, currentRefreshToken)
			if err != nil {
				return "", "", time.Time{}, err
			}
		}
		if err := s.tokens.DeleteRefreshToken(ctx, tenantID, spent.ID); err != nil {
			return "", "", time.Time{}, err
		}
	}
	refreshToken, plaintext, err := s.createRefreshToken(ctx, tenantID, request)
	if err != nil {
		return "", "", time.Time{}, err
	}
	accessToken, err := s.createAccessToken(ctx, tenantID, request, refreshToken.ID)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return accessToken.ID, plaintext, accessToken.Expires, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context,
	refreshToken string) (op.RefreshTokenRequest, error) {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	token, err := s.tokens.ReadRefreshToken(ctx, tenantID, refreshToken)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// TerminateSession ends one subject's grants at one client, which is what
// RP-initiated logout acts on.
func (s *Storage) TerminateSession(ctx context.Context, subject, clientID string) error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	return s.tokens.DeleteGrants(ctx, tenantID, subject, clientID)
}

// RevokeToken is reached with an id, not a token value: the library
// resolves a refresh token through GetRefreshTokenInfo first and passes the
// id on. Both kinds of id are uuids, so a refresh token is tried first and
// an access token second.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID, subject,
	clientID string) *oidc.Error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return oidc.ErrServerError().WithDescription("no tenant in context")
	}
	if _, err := s.tokens.ReadRefreshTokenByID(ctx, tenantID, tokenOrTokenID); err == nil {
		if err := s.tokens.DeleteRefreshToken(ctx, tenantID, tokenOrTokenID); err != nil {
			return oidc.ErrServerError().WithDescription("could not revoke refresh token")
		}
		return nil
	}
	err = s.tokens.DeleteAccessToken(ctx, tenantID, tokenOrTokenID)
	// Revoking an unknown token is a success per RFC 7009.
	if err != nil && !errors.As(err, &TokenNotFoundError{}) {
		return oidc.ErrServerError().WithDescription("could not revoke access token")
	}
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID,
	token string) (string, string, error) {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := s.tokens.ReadRefreshToken(ctx, tenantID, token)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	if refreshToken.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return refreshToken.Subject, refreshToken.ID, nil
}

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	client, err := s.clients.Client(ctx, tenantID, clientID)
	if err != nil {
		return nil, err
	}
	return &providerClient{
		client: client,
		loginURL: func(authRequestID string) string {
			return s.loginURL(tenantID, authRequestID)
		},
	}, nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, secret string) error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	return s.clients.Authenticate(ctx, tenantID, clientID, secret)
}

// SetUserinfoFromScopes is deprecated in the library and deliberately
// empty; SetUserinfoFromRequest is the live path.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, subject,
	clientID string, scopes []string) error {
	return nil
}

// SetUserinfoFromRequest shapes the claims for the id_token. The three the
// first consumer requires (email, email_verified, name) must be here: it
// reads them from the id_token only and never calls UserInfo.
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo,
	request op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, request.GetSubject(), scopes)
}

// SetUserinfoFromToken backs the UserInfo endpoint, reached with an opaque
// access token.
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID,
	subject, origin string) error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	token, err := s.tokens.ReadAccessToken(ctx, tenantID, tokenID)
	if err != nil {
		return err
	}
	return s.setUserinfo(ctx, userinfo, token.Subject, token.Scopes)
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context,
	introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	token, err := s.tokens.ReadAccessToken(ctx, tenantID, tokenID)
	if err != nil {
		return err
	}
	userinfo := new(oidc.UserInfo)
	if err := s.setUserinfo(ctx, userinfo, token.Subject, token.Scopes); err != nil {
		return err
	}
	introspection.SetUserInfo(userinfo)
	introspection.Scope = token.Scopes
	introspection.ClientID = token.ClientID
	return nil
}

// GetPrivateClaimsFromScopes is where claims outside the standard profile
// would go. an mints none: every scope it supports maps onto a registered
// claim, shaped in setUserinfo.
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, subject, clientID string,
	scopes []string) (map[string]any, error) {
	return nil, nil
}

// SigningKey returns the key the provider signs id_tokens with: an's own
// latest key, so the OIDC surface and the api-key surface share one JWKS.
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	s.keys.RLock()
	key := s.signingKey
	s.keys.RUnlock()
	if key == nil {
		if err := s.ReloadKeys(ctx); err != nil {
			return nil, err
		}
		s.keys.RLock()
		key = s.signingKey
		s.keys.RUnlock()
	}
	return key, nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet publishes every key, current and superseded, so tokens signed
// before a rotation still verify.
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	s.keys.RLock()
	keySet := s.keySet
	s.keys.RUnlock()
	if keySet == nil {
		if err := s.ReloadKeys(ctx); err != nil {
			return nil, err
		}
		s.keys.RLock()
		keySet = s.keySet
		s.keys.RUnlock()
	}
	return keySet, nil
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, subject string,
	scopes []string) ([]string, error) {
	return scopes, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID,
	clientID string) (*jose.JSONWebKey, error) {
	return nil, op.ErrInvalidRefreshToken
}

// setUserinfo is the single place claims are shaped, so the id_token and
// UserInfo cannot drift apart.
func (s *Storage) setUserinfo(ctx context.Context, userinfo *oidc.UserInfo, subject string,
	scopes []string) error {
	tenantID, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	account, err := s.accounts.ReadByID(ctx, tenantID, subject)
	if err != nil {
		return err
	}
	if account.Deleted || !account.Enabled {
		return accounts.AccountDisabledError{Value: account.Email}
	}
	userinfo.Subject = account.ID
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeEmail:
			userinfo.Email = account.Email
			userinfo.EmailVerified = oidc.Bool(account.Verified)
		case oidc.ScopeProfile:
			userinfo.Name = account.Name
		}
	}
	return nil
}

func (s *Storage) createAccessToken(ctx context.Context, tenantID string, request op.TokenRequest,
	refreshTokenID string) (*AccessToken, error) {
	clientID := ""
	if client, ok := request.(interface{ GetClientID() string }); ok {
		clientID = client.GetClientID()
	}
	return s.tokens.CreateAccessToken(ctx, AccessToken{
		TenantID:       tenantID,
		ClientID:       clientID,
		Subject:        request.GetSubject(),
		Audience:       request.GetAudience(),
		Scopes:         request.GetScopes(),
		RefreshTokenID: refreshTokenID,
		Expires:        time.Now().Add(s.accessExpiry),
	})
}

func (s *Storage) createRefreshToken(ctx context.Context, tenantID string,
	request op.TokenRequest) (*RefreshToken, string, error) {
	token := RefreshToken{
		TenantID: tenantID,
		Subject:  request.GetSubject(),
		Audience: request.GetAudience(),
		Scopes:   request.GetScopes(),
		AMR:      []string{},
		AuthTime: time.Now(),
		Expires:  time.Now().Add(s.refreshExpiry),
	}
	// Both an authorization request and a refresh request carry these;
	// asking for the methods is simpler than naming every type that has them.
	if source, ok := request.(interface {
		GetClientID() string
		GetAMR() []string
		GetAuthTime() time.Time
	}); ok {
		token.ClientID = source.GetClientID()
		token.AMR = source.GetAMR()
		token.AuthTime = source.GetAuthTime()
	}
	return s.tokens.CreateRefreshToken(ctx, token)
}

// signingKey adapts an's signing key to the provider's interface.
type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *signingKey) Key() any                                    { return k.key }
func (k *signingKey) ID() string                                  { return k.kid }

// publicKeyEntry adapts an's public key to the provider's JWKS interface.
type publicKeyEntry struct {
	kid string
	key *rsa.PublicKey
}

func (k *publicKeyEntry) ID() string                         { return k.kid }
func (k *publicKeyEntry) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *publicKeyEntry) Use() string                        { return "sig" }
func (k *publicKeyEntry) Key() any                           { return k.key }
