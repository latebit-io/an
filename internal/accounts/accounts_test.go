package accounts

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(utils.RunTestMain(m))
}

// revocations records session revocations and lockout clears so the tests
// can assert the service triggers them (the real implementations live in
// the authn package).
type revocations struct {
	revoked []string
	cleared []string
}

func (r *revocations) DeleteAll(ctx context.Context, tenantID, email string) error {
	r.revoked = append(r.revoked, tenantID+"/"+email)
	return nil
}

func (r *revocations) Clear(ctx context.Context, tenantID, email string) error {
	r.cleared = append(r.cleared, tenantID+"/"+email)
	return nil
}

func newService(t *testing.T) (AccountService, AccountRepository, *revocations) {
	pool := utils.NewTestPool(t)
	repository := NewPostgresAccountRepository(pool)
	resets := NewPostgresPasswordResetRepository(pool)
	recorder := &revocations{}
	service := NewDefaultAccountService(repository, resets, []SessionRevoker{recorder}, recorder,
		utils.NewPostgresTxManager(pool), 4, time.Hour)
	return service, repository, recorder
}

func TestRegister(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newService(t)

	registered, err := service.Register(ctx, "default", "user@example.com", "password-1", "")
	require.NoError(t, err)
	assert.NotEmpty(t, registered.ID)
	assert.NotEmpty(t, registered.VerificationToken)
	assert.False(t, registered.Verified)
	assert.True(t, registered.Enabled)
	assert.Empty(t, registered.PasswordHash)

	_, err = service.Register(ctx, "default", "user@example.com", "password-1", "")
	assert.ErrorAs(t, err, &AccountDuplicateError{})

	_, err = service.Register(ctx, "other", "user@example.com", "password-1", "")
	assert.NoError(t, err, "same email in another tenant is a different account")
}

func TestRegisterValidation(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newService(t)

	_, err := service.Register(ctx, "default", "not-an-email", "password-1", "")
	assert.ErrorAs(t, err, &InvalidAccountError{})
	_, err = service.Register(ctx, "default", "user@example.com", "short", "")
	assert.ErrorAs(t, err, &InvalidAccountError{})
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	service, repository, _ := newService(t)

	registered, err := service.Register(ctx, "default", "user@example.com", "password-1", "")
	require.NoError(t, err)

	err = service.Verify(ctx, "default", "user@example.com", "wrong-token")
	assert.ErrorAs(t, err, &VerificationError{})

	require.NoError(t, service.Verify(ctx, "default", "user@example.com", registered.VerificationToken))

	account, err := repository.Read(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.True(t, account.Verified)
	assert.Empty(t, account.VerificationHash)

	err = service.Verify(ctx, "default", "user@example.com", registered.VerificationToken)
	assert.ErrorAs(t, err, &VerificationError{}, "verifying twice fails")
}

func TestResendVerification(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newService(t)

	registered, err := service.Register(ctx, "default", "user@example.com", "password-1", "")
	require.NoError(t, err)

	token, err := service.ResendVerification(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.NotEqual(t, registered.VerificationToken, token)

	err = service.Verify(ctx, "default", "user@example.com", registered.VerificationToken)
	assert.ErrorAs(t, err, &VerificationError{}, "old token is dead after resend")
	require.NoError(t, service.Verify(ctx, "default", "user@example.com", token))

	_, err = service.ResendVerification(ctx, "default", "user@example.com")
	assert.ErrorAs(t, err, &VerificationError{}, "resend on a verified account fails")
}

func TestForgotAndReset(t *testing.T) {
	ctx := context.Background()
	service, repository, recorder := newService(t)

	registered, err := service.Register(ctx, "default", "user@example.com", "password-1", "")
	require.NoError(t, err)

	reset, err := service.Forgot(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, reset.Token)
	assert.True(t, reset.Expires.After(time.Now()))

	err = service.Reset(ctx, "default", "user@example.com", "wrong-token", "password-2")
	assert.ErrorAs(t, err, &ResetTokenInvalidError{})

	require.NoError(t, service.Reset(ctx, "default", "user@example.com", reset.Token, "password-2"))
	assert.Equal(t, []string{"default/user@example.com"}, recorder.revoked, "reset revokes sessions")
	assert.Equal(t, []string{"default/user@example.com"}, recorder.cleared, "reset clears lockout")

	account, err := repository.Read(ctx, "default", "user@example.com")
	require.NoError(t, err)
	match, err := utils.BcryptVerify(account.PasswordHash, "password-2")
	require.NoError(t, err)
	assert.True(t, match)

	err = service.Reset(ctx, "default", "user@example.com", reset.Token, "password-3")
	assert.ErrorAs(t, err, &ResetTokenInvalidError{}, "reset token is single use")

	_ = registered
}

func TestForgotUnknownAccount(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newService(t)

	_, err := service.Forgot(ctx, "default", "nobody@example.com")
	assert.ErrorAs(t, err, &AccountNotFoundError{})
}

func TestResetExpiredToken(t *testing.T) {
	ctx := context.Background()
	pool := utils.NewTestPool(t)
	repository := NewPostgresAccountRepository(pool)
	resets := NewPostgresPasswordResetRepository(pool)
	recorder := &revocations{}
	service := NewDefaultAccountService(repository, resets, []SessionRevoker{recorder}, recorder,
		utils.NewPostgresTxManager(pool), 4, -time.Minute)

	_, err := service.Register(ctx, "default", "user@example.com", "password-1", "")
	require.NoError(t, err)

	reset, err := service.Forgot(ctx, "default", "user@example.com")
	require.NoError(t, err)

	err = service.Reset(ctx, "default", "user@example.com", reset.Token, "password-2")
	assert.ErrorAs(t, err, &ResetTokenExpiredError{})
}

func TestUpdatePassword(t *testing.T) {
	ctx := context.Background()
	service, repository, _ := newService(t)

	_, err := service.Register(ctx, "default", "user@example.com", "password-1", "")
	require.NoError(t, err)

	err = service.UpdatePassword(ctx, "default", "user@example.com", "wrong", "password-2")
	assert.ErrorAs(t, err, &InvalidAccountError{})

	require.NoError(t, service.UpdatePassword(ctx, "default", "user@example.com", "password-1", "password-2"))

	account, err := repository.Read(ctx, "default", "user@example.com")
	require.NoError(t, err)
	match, err := utils.BcryptVerify(account.PasswordHash, "password-2")
	require.NoError(t, err)
	assert.True(t, match)
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	service, _, recorder := newService(t)

	_, err := service.Register(ctx, "default", "user@example.com", "password-1", "")
	require.NoError(t, err)

	require.NoError(t, service.Delete(ctx, "default", "user@example.com"))
	assert.Equal(t, []string{"default/user@example.com"}, recorder.revoked, "delete revokes sessions")

	_, err = service.Forgot(ctx, "default", "user@example.com")
	assert.ErrorAs(t, err, &AccountNotFoundError{}, "deleted account reads as not found")

	err = service.Delete(ctx, "default", "user@example.com")
	assert.ErrorAs(t, err, &AccountNotFoundError{})
}

func TestCreateVerified(t *testing.T) {
	ctx := context.Background()
	_, repository, _ := newService(t)

	hash, err := utils.BcryptHash("irrelevant", 4)
	require.NoError(t, err)
	account, err := repository.CreateVerified(ctx, Account{
		TenantID:     "default",
		Email:        "social@example.com",
		PasswordHash: hash,
	})
	require.NoError(t, err)
	assert.True(t, account.Verified)

	stored, err := repository.Read(ctx, "default", "social@example.com")
	require.NoError(t, err)
	assert.True(t, stored.Verified)
	assert.Empty(t, stored.VerificationHash)
}

// The name claim is the only profile field an holds. It is optional, and an
// absent name must stay absent rather than becoming an empty string, so the
// id_token omits the claim instead of asserting it empty.
func TestRegisterWithName(t *testing.T) {
	ctx := context.Background()
	service, repository, _ := newService(t)

	registered, err := service.Register(ctx, "default", "named@example.com", "password-1", "Ada Lovelace")
	require.NoError(t, err)
	assert.Equal(t, "Ada Lovelace", registered.Name)

	stored, err := repository.Read(ctx, "default", "named@example.com")
	require.NoError(t, err)
	assert.Equal(t, "Ada Lovelace", stored.Name)

	_, err = service.Register(ctx, "default", "anon@example.com", "password-1", "")
	require.NoError(t, err)
	anonymous, err := repository.Read(ctx, "default", "anon@example.com")
	require.NoError(t, err)
	assert.Empty(t, anonymous.Name)
}

func TestUpdateName(t *testing.T) {
	ctx := context.Background()
	service, repository, _ := newService(t)

	_, err := service.Register(ctx, "default", "user@example.com", "password-1", "Before")
	require.NoError(t, err)

	require.NoError(t, service.UpdateName(ctx, "default", "user@example.com", "After"))
	stored, err := repository.Read(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, "After", stored.Name)

	// Clearing drops the claim rather than asserting an empty one.
	require.NoError(t, service.UpdateName(ctx, "default", "user@example.com", ""))
	cleared, err := repository.Read(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.Empty(t, cleared.Name)

	err = service.UpdateName(ctx, "default", "user@example.com", string(make([]byte, 129)))
	assert.ErrorAs(t, err, &InvalidAccountError{})

	err = service.UpdateName(ctx, "default", "missing@example.com", "Nobody")
	assert.ErrorAs(t, err, &AccountNotFoundError{})
}

// ReadByID backs the OIDC subject lookup: sub is the account id, so every
// claim in the id_token is resolved from it rather than from the email.
func TestReadByID(t *testing.T) {
	ctx := context.Background()
	service, repository, _ := newService(t)

	registered, err := service.Register(ctx, "default", "user@example.com", "password-1", "Ada")
	require.NoError(t, err)

	account, err := repository.ReadByID(ctx, "default", registered.ID)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", account.Email)
	assert.Equal(t, "Ada", account.Name)

	// Another tenant must not resolve the same id.
	_, err = repository.ReadByID(ctx, "other", registered.ID)
	assert.ErrorAs(t, err, &AccountNotFoundError{})

	// A malformed id is a miss, not a database error.
	_, err = repository.ReadByID(ctx, "default", "not-a-uuid")
	assert.ErrorAs(t, err, &AccountNotFoundError{})
}
