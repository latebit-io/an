package tokens

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// UseAccess and UseRefresh travel in the JWT "use" header and are
	// enforced at validation so a refresh token can never pass as an
	// access token or vice versa.
	UseAccess  = "access"
	UseRefresh = "refresh"
)

// AccessClaims are the claims of an access token. There is no roles claim:
// an is pure authn, authorization lives in az.
type AccessClaims struct {
	TenantID string `json:"tenantId"`
	ClientID string `json:"clientId"`
	jwt.RegisteredClaims
}

// RefreshClaims are the claims of a refresh token.
type RefreshClaims struct {
	TenantID string `json:"tenantId"`
	ClientID string `json:"clientId"`
	jwt.RegisteredClaims
}

type Tokenizer interface {
	CreateAccessToken(ctx context.Context, tenantID, email, clientID string) (string, *AccessClaims, error)
	CreateRefreshToken(ctx context.Context, tenantID, email, clientID string) (string, *RefreshClaims, error)
	ValidateAccessToken(ctx context.Context, token string) (*AccessClaims, error)
	ValidateRefreshToken(ctx context.Context, token string) (*RefreshClaims, error)
}

type DefaultTokenizer struct {
	issuer   string
	audience string

	accessExpiry  time.Duration
	refreshExpiry time.Duration

	signingKid string
	signingKey *rsa.PrivateKey
	publicKeys map[string]*rsa.PublicKey
}

// NewDefaultTokenizer loads and parses all signing keys once: signs with the
// latest key, validates against any known kid. Call after
// SigningKeyService.Initialize.
func NewDefaultTokenizer(ctx context.Context, issuer, audience string, accessExpiryInSeconds,
	refreshExpiryInSeconds int, service SigningKeyService) (Tokenizer, error) {
	keys, err := service.Keys(ctx)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, NoSigningKeyError{}
	}
	publicKeys := make(map[string]*rsa.PublicKey, len(keys))
	for _, key := range keys {
		publicKey, err := parsePublicKey(key.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		publicKeys[key.Kid] = publicKey
	}
	latest := keys[len(keys)-1]
	privateKey, err := parsePrivateKey(latest.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &DefaultTokenizer{
		issuer:        issuer,
		audience:      audience,
		accessExpiry:  time.Duration(accessExpiryInSeconds) * time.Second,
		refreshExpiry: time.Duration(refreshExpiryInSeconds) * time.Second,
		signingKid:    latest.Kid,
		signingKey:    privateKey,
		publicKeys:    publicKeys,
	}, nil
}

func (t *DefaultTokenizer) CreateAccessToken(ctx context.Context, tenantID, email,
	clientID string) (string, *AccessClaims, error) {
	claims := &AccessClaims{
		TenantID:         tenantID,
		ClientID:         clientID,
		RegisteredClaims: t.registeredClaims(email, t.accessExpiry),
	}
	token, err := t.sign(claims, UseAccess)
	if err != nil {
		return "", nil, err
	}
	return token, claims, nil
}

func (t *DefaultTokenizer) CreateRefreshToken(ctx context.Context, tenantID, email,
	clientID string) (string, *RefreshClaims, error) {
	claims := &RefreshClaims{
		TenantID:         tenantID,
		ClientID:         clientID,
		RegisteredClaims: t.registeredClaims(email, t.refreshExpiry),
	}
	token, err := t.sign(claims, UseRefresh)
	if err != nil {
		return "", nil, err
	}
	return token, claims, nil
}

func (t *DefaultTokenizer) ValidateAccessToken(ctx context.Context, tokenString string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	if err := t.validate(tokenString, UseAccess, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (t *DefaultTokenizer) ValidateRefreshToken(ctx context.Context, tokenString string) (*RefreshClaims, error) {
	claims := &RefreshClaims{}
	if err := t.validate(tokenString, UseRefresh, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (t *DefaultTokenizer) registeredClaims(email string, expiry time.Duration) jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Subject:   email,
		Issuer:    t.issuer,
		Audience:  []string{t.audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
	}
}

func (t *DefaultTokenizer) sign(claims jwt.Claims, use string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = t.signingKid
	token.Header["use"] = use
	return token.SignedString(t.signingKey)
}

func (t *DefaultTokenizer) validate(tokenString, use string, claims jwt.Claims) error {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, TokenInvalidError{Reason: "signing method not supported"}
		}
		if tokenUse, _ := token.Header["use"].(string); tokenUse != use {
			return nil, TokenInvalidError{Reason: "wrong token use"}
		}
		kid, _ := token.Header["kid"].(string)
		publicKey, ok := t.publicKeys[kid]
		if !ok {
			return nil, TokenInvalidError{Reason: "unknown signing key"}
		}
		return publicKey, nil
	}, jwt.WithIssuer(t.issuer), jwt.WithAudience(t.audience), jwt.WithExpirationRequired())
	if err != nil {
		return TokenInvalidError{Reason: err.Error()}
	}
	if !token.Valid {
		return TokenInvalidError{Reason: "token is not valid"}
	}
	return nil
}
