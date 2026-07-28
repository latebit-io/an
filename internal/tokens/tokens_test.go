package tokens

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(utils.RunTestMain(m))
}

func newService(t *testing.T) SigningKeyService {
	pool := utils.NewTestPool(t)
	return NewDefaultSigningKeyService(NewPostgresSigningKeyRepository(pool))
}

func TestInitializeIsIdempotent(t *testing.T) {
	ctx := context.Background()
	service := newService(t)

	require.NoError(t, service.Initialize(ctx))
	require.NoError(t, service.Initialize(ctx))

	keys, err := service.Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "RS256", keys[0].Algorithm)
}

func TestLatestWithoutKeys(t *testing.T) {
	ctx := context.Background()
	service := newService(t)

	_, err := service.Latest(ctx)
	assert.ErrorAs(t, err, &NoSigningKeyError{})
}

func TestTokenRoundTrip(t *testing.T) {
	ctx := context.Background()
	service := newService(t)
	require.NoError(t, service.Initialize(ctx))

	tokenizer, err := NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, service)
	require.NoError(t, err)

	access, accessClaims, err := tokenizer.CreateAccessToken(ctx, "default", "user@example.com", "client-1")
	require.NoError(t, err)
	assert.NotEmpty(t, accessClaims.ID)

	claims, err := tokenizer.ValidateAccessToken(ctx, access)
	require.NoError(t, err)
	assert.Equal(t, "default", claims.TenantID)
	assert.Equal(t, "client-1", claims.ClientID)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, accessClaims.ID, claims.ID)

	refresh, refreshClaims, err := tokenizer.CreateRefreshToken(ctx, "default", "user@example.com", "client-1")
	require.NoError(t, err)
	parsed, err := tokenizer.ValidateRefreshToken(ctx, refresh)
	require.NoError(t, err)
	assert.Equal(t, refreshClaims.ID, parsed.ID)
}

func TestUseHeaderIsEnforced(t *testing.T) {
	ctx := context.Background()
	service := newService(t)
	require.NoError(t, service.Initialize(ctx))

	tokenizer, err := NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, service)
	require.NoError(t, err)

	access, _, err := tokenizer.CreateAccessToken(ctx, "default", "user@example.com", "client-1")
	require.NoError(t, err)
	refresh, _, err := tokenizer.CreateRefreshToken(ctx, "default", "user@example.com", "client-1")
	require.NoError(t, err)

	_, err = tokenizer.ValidateAccessToken(ctx, refresh)
	assert.ErrorAs(t, err, &TokenInvalidError{})
	_, err = tokenizer.ValidateRefreshToken(ctx, access)
	assert.ErrorAs(t, err, &TokenInvalidError{})
}

func TestExpiredTokenIsRejected(t *testing.T) {
	ctx := context.Background()
	service := newService(t)
	require.NoError(t, service.Initialize(ctx))

	tokenizer, err := NewDefaultTokenizer(ctx, "an", "an", -1, -1, service)
	require.NoError(t, err)

	access, _, err := tokenizer.CreateAccessToken(ctx, "default", "user@example.com", "client-1")
	require.NoError(t, err)

	_, err = tokenizer.ValidateAccessToken(ctx, access)
	assert.ErrorAs(t, err, &TokenInvalidError{})
}

func TestUnknownIssuerAndAudienceRejected(t *testing.T) {
	ctx := context.Background()
	service := newService(t)
	require.NoError(t, service.Initialize(ctx))

	issuing, err := NewDefaultTokenizer(ctx, "someone-else", "someone-else", 3600, 86400, service)
	require.NoError(t, err)
	validating, err := NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, service)
	require.NoError(t, err)

	access, _, err := issuing.CreateAccessToken(ctx, "default", "user@example.com", "client-1")
	require.NoError(t, err)

	_, err = validating.ValidateAccessToken(ctx, access)
	assert.ErrorAs(t, err, &TokenInvalidError{})
}

func TestUnknownKidIsRejected(t *testing.T) {
	ctx := context.Background()

	serviceA := newService(t)
	require.NoError(t, serviceA.Initialize(ctx))
	serviceB := newService(t)
	require.NoError(t, serviceB.Initialize(ctx))

	issuing, err := NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, serviceA)
	require.NoError(t, err)
	validating, err := NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, serviceB)
	require.NoError(t, err)

	access, _, err := issuing.CreateAccessToken(ctx, "default", "user@example.com", "client-1")
	require.NoError(t, err)

	_, err = validating.ValidateAccessToken(ctx, access)
	assert.ErrorAs(t, err, &TokenInvalidError{})
}

// TestJWKSVerifiesToken proves a consumer can verify an access token with
// nothing but the published JWKS.
func TestJWKSVerifiesToken(t *testing.T) {
	ctx := context.Background()
	service := newService(t)
	require.NoError(t, service.Initialize(ctx))

	tokenizer, err := NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, service)
	require.NoError(t, err)
	access, _, err := tokenizer.CreateAccessToken(ctx, "default", "user@example.com", "client-1")
	require.NoError(t, err)

	keySet, err := service.JWKS(ctx)
	require.NoError(t, err)
	require.Len(t, keySet.Keys, 1)
	jwk := keySet.Keys[0]
	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)

	modulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
	require.NoError(t, err)
	exponent, err := base64.RawURLEncoding.DecodeString(jwk.E)
	require.NoError(t, err)
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(new(big.Int).SetBytes(exponent).Int64()),
	}

	parsed, err := jwt.ParseWithClaims(access, &AccessClaims{}, func(token *jwt.Token) (any, error) {
		require.Equal(t, jwk.Kid, token.Header["kid"])
		return publicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	claims := parsed.Claims.(*AccessClaims)
	assert.Equal(t, "default", claims.TenantID)
	assert.True(t, claims.ExpiresAt.After(time.Now()))
}

// A rotation must reach a running service: external relying parties verify
// against the published JWKS, so an issuer that needs a restart to roll a
// key cannot roll one at all.
func TestReloadKeysPicksUpRotation(t *testing.T) {
	ctx := context.Background()
	pool := utils.NewTestPool(t)
	repository := NewPostgresSigningKeyRepository(pool)
	service := NewDefaultSigningKeyService(repository)
	require.NoError(t, service.Initialize(ctx))

	tokenizer, err := NewDefaultTokenizer(ctx, "an", "an", 60, 60, service)
	require.NoError(t, err)

	before, _, err := tokenizer.CreateAccessToken(ctx, "default", "user@example.com", "web")
	require.NoError(t, err)
	firstKid := kidOf(t, before)

	// Rotation is an insert of a newer key.
	rotated, err := generateSigningKey()
	require.NoError(t, err)
	require.NoError(t, repository.Create(ctx, *rotated))

	// Still signing with the old key until the reload.
	stale, _, err := tokenizer.CreateAccessToken(ctx, "default", "user@example.com", "web")
	require.NoError(t, err)
	assert.Equal(t, firstKid, kidOf(t, stale))

	require.NoError(t, tokenizer.ReloadKeys(ctx))

	after, _, err := tokenizer.CreateAccessToken(ctx, "default", "user@example.com", "web")
	require.NoError(t, err)
	assert.Equal(t, rotated.Kid, kidOf(t, after))
	assert.NotEqual(t, firstKid, kidOf(t, after))

	// Tokens signed by the superseded key still validate: rotation adds a
	// key, it does not retire the old one.
	_, err = tokenizer.ValidateAccessToken(ctx, before)
	assert.NoError(t, err)
}

func kidOf(t *testing.T, token string) string {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	kid, _ := parsed.Header["kid"].(string)
	require.NotEmpty(t, kid)
	return kid
}
