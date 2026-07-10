package authn

import (
	"context"
	"testing"
	"time"

	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type codeHarness struct {
	*harness
	codes LogonCodeService
	repo2 LogonCodeRepository
}

func newCodeHarness(t *testing.T, expiry time.Duration) *codeHarness {
	h := newHarness(t, 3, time.Hour)
	pool := h.pool
	repository := NewPostgresLogonCodeRepository(pool)
	return &codeHarness{
		harness: h,
		codes:   NewDefaultLogonCodeService(h.service, h.repo, repository, expiry, 4),
		repo2:   repository,
	}
}

func TestLogonCodeFlow(t *testing.T) {
	ctx := context.Background()
	h := newCodeHarness(t, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	issued, err := h.codes.Request(ctx, "default", "user@example.com")
	require.NoError(t, err)
	require.NoError(t, utils.ValidateCode(issued.Code, 6))
	assert.True(t, issued.Expires.After(time.Now()))

	authenticated, err := h.codes.Authenticate(ctx, "default", "user@example.com", "client-1", issued.Code)
	require.NoError(t, err)
	assert.NotEmpty(t, authenticated.AccessToken)

	_, err = h.codes.Authenticate(ctx, "default", "user@example.com", "client-1", issued.Code)
	assert.ErrorAs(t, err, &LogonCodeInvalidError{}, "a code is single use")
}

func TestLogonCodeUnknownAccount(t *testing.T) {
	ctx := context.Background()
	h := newCodeHarness(t, time.Minute)

	_, err := h.codes.Request(ctx, "default", "nobody@example.com")
	assert.ErrorAs(t, err, &accounts.AccountNotFoundError{})

	_, err = h.codes.Authenticate(ctx, "default", "nobody@example.com", "client-1", "123456")
	assert.ErrorAs(t, err, &AuthenticationError{})
}

func TestLogonCodeWrongCodeCountsTowardLockout(t *testing.T) {
	ctx := context.Background()
	h := newCodeHarness(t, time.Minute)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	issued, err := h.codes.Request(ctx, "default", "user@example.com")
	require.NoError(t, err)

	wrong := "000000"
	if issued.Code == wrong {
		wrong = "000001"
	}
	for range 2 {
		_, err := h.codes.Authenticate(ctx, "default", "user@example.com", "client-1", wrong)
		assert.ErrorAs(t, err, &AuthenticationError{})
	}
	_, err = h.codes.Authenticate(ctx, "default", "user@example.com", "client-1", wrong)
	assert.ErrorAs(t, err, &AccountLockedError{}, "code failures lock like password failures")

	_, err = h.codes.Authenticate(ctx, "default", "user@example.com", "client-1", issued.Code)
	assert.ErrorAs(t, err, &AccountLockedError{}, "even the right code is locked out")
}

func TestLogonCodeExpiry(t *testing.T) {
	ctx := context.Background()
	h := newCodeHarness(t, -time.Second)
	h.registerVerified(t, "default", "user@example.com", "password-1")

	issued, err := h.codes.Request(ctx, "default", "user@example.com")
	require.NoError(t, err)

	_, err = h.codes.Authenticate(ctx, "default", "user@example.com", "client-1", issued.Code)
	assert.ErrorAs(t, err, &LogonCodeExpiredError{}, "expiry is enforced on read")

	deleted, err := h.repo2.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}

func TestLogonCodeVerifiesAccount(t *testing.T) {
	ctx := context.Background()
	h := newCodeHarness(t, time.Minute)

	_, err := h.accounts.Register(ctx, "default", "user@example.com", "password-1")
	require.NoError(t, err)

	issued, err := h.codes.Request(ctx, "default", "user@example.com")
	require.NoError(t, err, "unverified accounts may request codes")

	_, err = h.codes.Authenticate(ctx, "default", "user@example.com", "client-1", issued.Code)
	require.NoError(t, err)

	account, err := h.repo.Read(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.True(t, account.Verified, "a code logon proves mailbox ownership")
}
