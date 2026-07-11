package integration

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	an "github.com/latebit-io/an-client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	baseURI = "http://localhost:8080"
	apiKey  string
	client  *an.Client
)

func TestMain(m *testing.M) {
	if uri := os.Getenv("AN_BASE_URI"); uri != "" {
		baseURI = uri
	}
	apiKey = os.Getenv("API_KEY")
	client = an.NewClient(baseURI, apiKey, nil)

	// wait for the service to be reachable
	ready := false
	for range 30 {
		response, err := http.Get(baseURI + "/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(time.Second)
	}
	if !ready {
		fmt.Fprintln(os.Stderr, "an service not reachable on "+baseURI+" — start it with docker-compose up")
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// newTenant returns a unique tenant id so runs are isolated and repeatable
// against the same database.
func newTenant() string {
	return "t" + uuid.NewString()[:12]
}

// registerVerified provisions a verified account ready to log on.
func registerVerified(t *testing.T, tenant, email, password string) {
	ctx := context.Background()
	registered, err := client.Accounts.Register(ctx, tenant, email, password)
	require.NoError(t, err)
	require.NotEmpty(t, registered.VerificationToken)
	require.NoError(t, client.Accounts.Verify(ctx, tenant, email, registered.VerificationToken))
}

func TestFullPasswordLifecycle(t *testing.T) {
	ctx := context.Background()
	tenant := newTenant()

	registered, err := client.Accounts.Register(ctx, tenant, "user@example.com", "password-1")
	require.NoError(t, err)
	assert.False(t, registered.Verified)

	// logging on before verification is forbidden
	_, err = client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-1")
	problem := requireProblem(t, err)
	assert.Equal(t, http.StatusForbidden, problem.Status)

	require.NoError(t, client.Accounts.Verify(ctx, tenant, "user@example.com", registered.VerificationToken))

	tokens, err := client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-1")
	require.NoError(t, err)

	// tokens are inert until acknowledged
	_, err = client.Authenticate.Validate(ctx, tenant, tokens.AccessToken)
	problem = requireProblem(t, err)
	assert.Equal(t, http.StatusUnauthorized, problem.Status)

	require.NoError(t, client.Authenticate.Acknowledge(ctx, tenant, *tokens))
	claims, err := client.Authenticate.Validate(ctx, tenant, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, "phone", claims.ClientID)
	assert.Equal(t, tenant, claims.TenantID)

	renewed, err := client.Authenticate.Renew(ctx, tenant, tokens.RefreshToken)
	require.NoError(t, err)

	_, err = client.Authenticate.Renew(ctx, tenant, tokens.RefreshToken)
	problem = requireProblem(t, err)
	assert.Equal(t, http.StatusUnauthorized, problem.Status, "rotated-away refresh token is dead")

	_, err = client.Authenticate.Validate(ctx, tenant, renewed.AccessToken)
	require.NoError(t, err)

	require.NoError(t, client.Authenticate.Revoke(ctx, tenant, "user@example.com", "phone"))
	_, err = client.Authenticate.Validate(ctx, tenant, renewed.AccessToken)
	problem = requireProblem(t, err)
	assert.Equal(t, http.StatusUnauthorized, problem.Status, "revoked session no longer validates")
}

func TestRevokePerClient(t *testing.T) {
	ctx := context.Background()
	tenant := newTenant()
	registerVerified(t, tenant, "user@example.com", "password-1")

	phone, err := client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-1")
	require.NoError(t, err)
	require.NoError(t, client.Authenticate.Acknowledge(ctx, tenant, *phone))
	laptop, err := client.Authenticate.Password(ctx, tenant, "user@example.com", "laptop", "password-1")
	require.NoError(t, err)
	require.NoError(t, client.Authenticate.Acknowledge(ctx, tenant, *laptop))

	require.NoError(t, client.Authenticate.Revoke(ctx, tenant, "user@example.com", "phone"))

	_, err = client.Authenticate.Validate(ctx, tenant, phone.AccessToken)
	require.Error(t, err)
	_, err = client.Authenticate.Validate(ctx, tenant, laptop.AccessToken)
	require.NoError(t, err, "the other client stays signed in")
}

func TestForgotAndReset(t *testing.T) {
	ctx := context.Background()
	tenant := newTenant()
	registerVerified(t, tenant, "user@example.com", "password-1")

	tokens, err := client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-1")
	require.NoError(t, err)
	require.NoError(t, client.Authenticate.Acknowledge(ctx, tenant, *tokens))

	reset, err := client.Accounts.Forgot(ctx, tenant, "user@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, reset.Token)

	require.NoError(t, client.Accounts.Reset(ctx, tenant, "user@example.com", reset.Token, "password-2"))

	_, err = client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-1")
	require.Error(t, err, "old password is dead")

	_, err = client.Authenticate.Validate(ctx, tenant, tokens.AccessToken)
	require.Error(t, err, "reset revokes existing sessions")

	_, err = client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-2")
	require.NoError(t, err)
}

func TestLockout(t *testing.T) {
	ctx := context.Background()
	tenant := newTenant()
	registerVerified(t, tenant, "user@example.com", "password-1")

	var problem *an.Error
	for range 5 {
		_, err := client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "wrong")
		problem = requireProblem(t, err)
	}
	assert.Equal(t, http.StatusLocked, problem.Status, "fifth failure locks")

	_, err := client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-1")
	problem = requireProblem(t, err)
	assert.Equal(t, http.StatusLocked, problem.Status, "even the right password is locked out")
}

func TestMagicCodeLifecycle(t *testing.T) {
	ctx := context.Background()
	tenant := newTenant()

	// register only — the code logon itself proves mailbox ownership
	_, err := client.Accounts.Register(ctx, tenant, "user@example.com", "password-1")
	require.NoError(t, err)

	issued, err := client.Authenticate.RequestCode(ctx, tenant, "user@example.com")
	require.NoError(t, err)
	require.Len(t, issued.Code, 6)

	tokens, err := client.Authenticate.Code(ctx, tenant, "user@example.com", "phone", issued.Code)
	require.NoError(t, err)

	_, err = client.Authenticate.Code(ctx, tenant, "user@example.com", "phone", issued.Code)
	require.Error(t, err, "a code is single use")

	require.NoError(t, client.Authenticate.Acknowledge(ctx, tenant, *tokens))
	claims, err := client.Authenticate.Validate(ctx, tenant, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)

	// the code logon verified the account, so passwords work now
	_, err = client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-1")
	require.NoError(t, err)
}

// TestJWKSVerifiesTokenLocally proves a consumer can verify access tokens
// with nothing but the published JWKS.
func TestJWKSVerifiesTokenLocally(t *testing.T) {
	ctx := context.Background()
	tenant := newTenant()
	registerVerified(t, tenant, "user@example.com", "password-1")

	tokens, err := client.Authenticate.Password(ctx, tenant, "user@example.com", "phone", "password-1")
	require.NoError(t, err)

	keySet, err := client.JWKS(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, keySet.Keys)

	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range keySet.Keys {
		modulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
		require.NoError(t, err)
		exponent, err := base64.RawURLEncoding.DecodeString(jwk.E)
		require.NoError(t, err)
		keys[jwk.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Int64()),
		}
	}

	parsed, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}
		return key, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestApiKeyTenantScoping(t *testing.T) {
	if apiKey == "" {
		t.Skip("API_KEY not set — auth is disabled on the target service")
	}
	ctx := context.Background()
	tenantA := newTenant()
	tenantB := newTenant()

	// no key → 401
	_, err := an.NewClient(baseURI, "", nil).Accounts.Register(ctx, tenantA, "user@example.com", "password-1")
	problem := requireProblem(t, err)
	assert.Equal(t, http.StatusUnauthorized, problem.Status)

	// bootstrap mints a tenant-scoped key
	created, err := client.APIKeys.Create(ctx, tenantA, "integration")
	require.NoError(t, err)
	require.NotEmpty(t, created.Key)
	tenantClient := an.NewClient(baseURI, created.Key, nil)

	// a tenant key cannot escape its tenant: the requested tenantB is
	// overridden by the key's tenantA
	registered, err := tenantClient.Accounts.Register(ctx, tenantB, "scoped@example.com", "password-1")
	require.NoError(t, err)
	assert.Equal(t, tenantA, registered.TenantID)

	// a tenant key cannot manage keys
	_, err = tenantClient.APIKeys.Create(ctx, tenantA, "escalation")
	problem = requireProblem(t, err)
	assert.Equal(t, http.StatusForbidden, problem.Status)

	// revoked key stops working
	require.NoError(t, client.APIKeys.Revoke(ctx, tenantA, created.ID))
	_, err = tenantClient.Accounts.Register(ctx, tenantA, "second@example.com", "password-1")
	problem = requireProblem(t, err)
	assert.Equal(t, http.StatusUnauthorized, problem.Status)
}

func TestProblemDetailsShape(t *testing.T) {
	ctx := context.Background()
	tenant := newTenant()

	_, err := client.Accounts.Forgot(ctx, tenant, "nobody@example.com")
	problem := requireProblem(t, err)
	assert.Equal(t, "https://latebit.io/an/errors/", problem.Type)
	assert.Equal(t, http.StatusNotFound, problem.Status)
	assert.NotEmpty(t, problem.Detail)
}

func requireProblem(t *testing.T, err error) *an.Error {
	t.Helper()
	require.Error(t, err)
	var problem *an.Error
	require.True(t, errors.As(err, &problem), "expected problem details, got: %v", err)
	return problem
}
