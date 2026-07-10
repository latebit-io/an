package social

import (
	"context"
	"os"
	"testing"

	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/authn"
	"github.com/latebit-io/an/internal/tokens"
	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(utils.RunTestMain(m))
}

// fakeValidator plays a provider so the tests exercise the service without
// Google; GoogleValidator is only OIDC plumbing on top of the same
// interface.
type fakeValidator struct {
	name     string
	identity *Identity
	err      error
}

func (f *fakeValidator) Name() string {
	return f.name
}

func (f *fakeValidator) Validate(ctx context.Context, idToken string) (*Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.identity, nil
}

type socialHarness struct {
	service   SocialService
	accounts  accounts.AccountRepository
	tokenizer tokens.Tokenizer
	validator *fakeValidator
}

func newSocialHarness(t *testing.T) *socialHarness {
	ctx := context.Background()
	pool := utils.NewTestPool(t)

	signingKeys := tokens.NewDefaultSigningKeyService(tokens.NewPostgresSigningKeyRepository(pool))
	require.NoError(t, signingKeys.Initialize(ctx))
	tokenizer, err := tokens.NewDefaultTokenizer(ctx, "an", "an", 3600, 86400, signingKeys)
	require.NoError(t, err)

	accountRepository := accounts.NewPostgresAccountRepository(pool)
	service := NewDefaultSocialService(accountRepository, NewPostgresSocialRepository(pool),
		tokenizer, 4)
	validator := &fakeValidator{
		name: "google",
		identity: &Identity{
			Provider:      "google",
			Subject:       "google-subject-1",
			Email:         "user@example.com",
			EmailVerified: true,
		},
	}
	service.AddValidator(validator)

	return &socialHarness{
		service:   service,
		accounts:  accountRepository,
		tokenizer: tokenizer,
		validator: validator,
	}
}

func TestSocialFirstLogonCreatesVerifiedAccount(t *testing.T) {
	ctx := context.Background()
	h := newSocialHarness(t)

	authenticated, err := h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	require.NoError(t, err)
	assert.NotEmpty(t, authenticated.AccessToken)
	assert.NotEmpty(t, authenticated.RefreshToken)

	account, err := h.accounts.Read(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.True(t, account.Verified, "social accounts are born verified")

	claims, err := h.tokenizer.ValidateAccessToken(ctx, authenticated.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)
}

func TestSocialLogonExistingAccount(t *testing.T) {
	ctx := context.Background()
	h := newSocialHarness(t)

	hash, err := utils.BcryptHash("password-1", 4)
	require.NoError(t, err)
	_, err = h.accounts.Create(ctx, accounts.Account{
		TenantID:         "default",
		Email:            "user@example.com",
		PasswordHash:     hash,
		VerificationHash: "pending",
	})
	require.NoError(t, err)

	_, err = h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	require.NoError(t, err)

	account, err := h.accounts.Read(ctx, "default", "user@example.com")
	require.NoError(t, err)
	assert.True(t, account.Verified, "google asserting the email verifies the account")

	_, err = h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	assert.NoError(t, err, "re-linking the same identity is idempotent")
}

func TestSocialUnverifiedEmailRejected(t *testing.T) {
	ctx := context.Background()
	h := newSocialHarness(t)
	h.validator.identity.EmailVerified = false

	_, err := h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	assert.ErrorAs(t, err, &EmailNotVerifiedError{})

	_, err = h.accounts.Read(ctx, "default", "user@example.com")
	assert.ErrorAs(t, err, &accounts.AccountNotFoundError{}, "no account is created")
}

func TestSocialUnknownProvider(t *testing.T) {
	ctx := context.Background()
	h := newSocialHarness(t)

	_, err := h.service.Authenticate(ctx, "default", "microsoft", "id-token", "client-1")
	assert.ErrorAs(t, err, &ProviderNotConfiguredError{})
}

func TestSocialInvalidToken(t *testing.T) {
	ctx := context.Background()
	h := newSocialHarness(t)
	h.validator.err = SocialTokenInvalidError{Value: "expired"}

	_, err := h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	assert.ErrorAs(t, err, &SocialTokenInvalidError{})
}

func TestSocialIdentityLinkedToOtherAccount(t *testing.T) {
	ctx := context.Background()
	h := newSocialHarness(t)

	_, err := h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	require.NoError(t, err)

	// The same google subject now asserts a different email: it must not
	// link to a second account.
	h.validator.identity.Email = "other@example.com"
	_, err = h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	assert.ErrorAs(t, err, &SocialAlreadyLinkedError{})
}

func TestSocialDeletedAccountRejected(t *testing.T) {
	ctx := context.Background()
	h := newSocialHarness(t)

	_, err := h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	require.NoError(t, err)
	require.NoError(t, h.accounts.SoftDelete(ctx, "default", "user@example.com"))

	_, err = h.service.Authenticate(ctx, "default", "google", "id-token", "client-1")
	assert.ErrorAs(t, err, &authn.AuthenticationError{})
}
