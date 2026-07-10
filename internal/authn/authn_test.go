package authn

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/tokens"
	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(utils.RunTestMain(m))
}

type harness struct {
	pool      *pgxpool.Pool
	service   *DefaultAuthenticationService
	accounts  accounts.AccountService
	repo      accounts.AccountRepository
	sessions  SessionRepository
	attempts  FailedAttemptRepository
	tokenizer tokens.Tokenizer
}

func newHarness(t *testing.T, maxAttempts int, lockFor time.Duration) *harness {
	ctx := context.Background()
	pool := utils.NewTestPool(t)

	signingKeys := tokens.NewDefaultSigningKeyService(tokens.NewPostgresSigningKeyRepository(pool))
	require.NoError(t, signingKeys.Initialize(ctx))
	tokenizer, err := tokens.NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, signingKeys)
	require.NoError(t, err)

	sessions := NewPostgresSessionRepository(pool)
	attempts := NewPostgresFailedAttemptRepository(pool)
	accountRepository := accounts.NewPostgresAccountRepository(pool)
	accountService := accounts.NewDefaultAccountService(accountRepository,
		accounts.NewPostgresPasswordResetRepository(pool), sessions, attempts,
		utils.NewPostgresTxManager(pool), 4, time.Hour)

	return &harness{
		pool: pool,
		service: NewDefaultAuthenticationService(accountRepository, sessions, attempts,
			tokenizer, maxAttempts, lockFor),
		accounts:  accountService,
		repo:      accountRepository,
		sessions:  sessions,
		attempts:  attempts,
		tokenizer: tokenizer,
	}
}

// registerVerified registers and verifies an account ready to log on.
func (h *harness) registerVerified(t *testing.T, tenantID, email, password string) {
	ctx := context.Background()
	registered, err := h.accounts.Register(ctx, tenantID, email, password)
	require.NoError(t, err)
	require.NoError(t, h.accounts.Verify(ctx, tenantID, email, registered.VerificationToken))
}

func (h *harness) logonAndAck(t *testing.T, tenantID, email, password, clientID string) *Authenticated {
	ctx := context.Background()
	authenticated, err := h.service.Authenticate(ctx, tenantID, email, clientID, password)
	require.NoError(t, err)
	require.NoError(t, h.service.Acknowledge(ctx, tenantID, *authenticated))
	return authenticated
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	authenticated, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "password-1")
	require.NoError(t, err)
	assert.NotEmpty(t, authenticated.AccessToken)
	assert.NotEmpty(t, authenticated.RefreshToken)

	_, err = h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "wrong")
	assert.ErrorAs(t, err, &AuthenticationError{})

	_, err = h.service.Authenticate(ctx, "default", "nobody@example.com", "client-1", "password-1")
	assert.ErrorAs(t, err, &AuthenticationError{}, "unknown account fails like a wrong password")
}

func TestAuthenticateGates(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)

	registered, err := h.accounts.Register(ctx, "default", "unverified@example.com", "password-1")
	require.NoError(t, err)
	_, err = h.service.Authenticate(ctx, "default", "unverified@example.com", "client-1", "password-1")
	assert.ErrorAs(t, err, &accounts.AccountNotVerifiedError{})

	require.NoError(t, h.accounts.Verify(ctx, "default", "unverified@example.com",
		registered.VerificationToken))
	require.NoError(t, h.accounts.Delete(ctx, "default", "unverified@example.com"))
	_, err = h.service.Authenticate(ctx, "default", "unverified@example.com", "client-1", "password-1")
	assert.ErrorAs(t, err, &AuthenticationError{}, "deleted account fails like a wrong password")
}

func TestValidateRequiresAcknowledge(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	authenticated, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "password-1")
	require.NoError(t, err)

	_, err = h.service.Validate(ctx, "default", authenticated.AccessToken)
	assert.ErrorAs(t, err, &TokenNotAcknowledgedError{}, "unacknowledged token does not validate")

	require.NoError(t, h.service.Acknowledge(ctx, "default", *authenticated))
	claims, err := h.service.Validate(ctx, "default", authenticated.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, "client-1", claims.ClientID)

	_, err = h.service.Validate(ctx, "other", authenticated.AccessToken)
	assert.ErrorAs(t, err, &TokenTenantMismatchError{})
}

func TestAcknowledgeRejectsMismatchedPair(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	one, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "password-1")
	require.NoError(t, err)
	two, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-2", "password-1")
	require.NoError(t, err)

	err = h.service.Acknowledge(ctx, "default", Authenticated{
		AccessToken:  one.AccessToken,
		RefreshToken: two.RefreshToken,
	})
	assert.ErrorAs(t, err, &tokens.TokenInvalidError{}, "tokens from different clients do not pair")

	err = h.service.Acknowledge(ctx, "other", *one)
	assert.ErrorAs(t, err, &TokenTenantMismatchError{})
}

func TestRenewRotatesRefreshToken(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")
	authenticated := h.logonAndAck(t, "default", "user@example.com", "password-1", "client-1")

	renewed, err := h.service.Renew(ctx, "default", authenticated.RefreshToken)
	require.NoError(t, err)
	assert.NotEqual(t, authenticated.RefreshToken, renewed.RefreshToken)

	_, err = h.service.Renew(ctx, "default", authenticated.RefreshToken)
	assert.ErrorAs(t, err, &TokenNotAcknowledgedError{}, "rotated-away refresh token is dead")

	again, err := h.service.Renew(ctx, "default", renewed.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, again.AccessToken)

	_, err = h.service.Validate(ctx, "default", again.AccessToken)
	require.NoError(t, err, "renewed tokens are acknowledged implicitly")
}

func TestRenewRequiresAcknowledge(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	authenticated, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "password-1")
	require.NoError(t, err)

	_, err = h.service.Renew(ctx, "default", authenticated.RefreshToken)
	assert.ErrorAs(t, err, &TokenNotAcknowledgedError{})
}

// TestRevokePerClient is the regression test for the bulwarkauth bug where
// token reads ignored clientId: revoking one client must leave the other
// client's session intact.
func TestRevokePerClient(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	phone := h.logonAndAck(t, "default", "user@example.com", "password-1", "phone")
	laptop := h.logonAndAck(t, "default", "user@example.com", "password-1", "laptop")

	require.NoError(t, h.service.Revoke(ctx, "default", "user@example.com", "phone"))

	_, err := h.service.Validate(ctx, "default", phone.AccessToken)
	assert.ErrorAs(t, err, &TokenNotAcknowledgedError{}, "revoked client is signed out")
	_, err = h.service.Validate(ctx, "default", laptop.AccessToken)
	assert.NoError(t, err, "the other client stays signed in")

	err = h.service.Revoke(ctx, "default", "user@example.com", "phone")
	assert.ErrorAs(t, err, &SessionNotFoundError{})
}

func TestRevokeAllClients(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	phone := h.logonAndAck(t, "default", "user@example.com", "password-1", "phone")
	laptop := h.logonAndAck(t, "default", "user@example.com", "password-1", "laptop")

	require.NoError(t, h.service.Revoke(ctx, "default", "user@example.com", ""))

	_, err := h.service.Validate(ctx, "default", phone.AccessToken)
	assert.ErrorAs(t, err, &TokenNotAcknowledgedError{})
	_, err = h.service.Validate(ctx, "default", laptop.AccessToken)
	assert.ErrorAs(t, err, &TokenNotAcknowledgedError{})
}

func TestLockout(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 3, time.Hour)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	for range 2 {
		_, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "wrong")
		assert.ErrorAs(t, err, &AuthenticationError{})
	}

	_, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "wrong")
	var locked AccountLockedError
	require.ErrorAs(t, err, &locked, "the third failure locks")
	assert.True(t, locked.LockedUntil.After(time.Now()))

	_, err = h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "password-1")
	assert.ErrorAs(t, err, &AccountLockedError{}, "even the right password is locked out")
}

func TestLockoutExpiresAndClears(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 2, -time.Second) // lock instantly expires
	h.registerVerified(t, "default", "user@example.com", "password-1")

	for range 2 {
		_, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "wrong")
		require.Error(t, err)
	}

	authenticated, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "password-1")
	require.NoError(t, err, "expired lock unlocks and resets the counter")
	assert.NotEmpty(t, authenticated.AccessToken)

	attempt, err := h.attempts.Get(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.Nil(t, attempt, "successful logon clears the attempts row")
}

func TestLockoutSuccessResetsCounter(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 3, time.Hour)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	for range 2 {
		_, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "wrong")
		require.Error(t, err)
	}
	_, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "password-1")
	require.NoError(t, err)

	for range 2 {
		_, err := h.service.Authenticate(ctx, "default", "user@example.com", "client-1", "wrong")
		assert.ErrorAs(t, err, &AuthenticationError{}, "counter restarted after success")
	}
}

// TestIncrementAndLockIsAtomic hammers the counter concurrently: exactly
// max attempts must lock, with no lost updates.
func TestIncrementAndLockIsAtomic(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Hour)

	const workers = 20
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.attempts.IncrementAndLock(ctx, "default", "user@example.com", 5, time.Hour)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	attempt, err := h.attempts.Get(ctx, "default", "user@example.com")
	require.NoError(t, err)
	require.NotNil(t, attempt)
	assert.Equal(t, workers, attempt.Count, "no lost updates")
	require.NotNil(t, attempt.LockedUntil)
	assert.True(t, attempt.LockedUntil.After(time.Now()))
}

func TestSessionExpiryCleanup(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, 5, time.Minute)

	require.NoError(t, h.sessions.Upsert(ctx, Session{
		TenantID:   "default",
		Email:      "user@example.com",
		ClientID:   "client-1",
		RefreshJTI: "018f6f00-0000-7000-8000-000000000000",
		Expires:    time.Now().Add(-time.Hour),
	}))

	deleted, err := h.sessions.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}
