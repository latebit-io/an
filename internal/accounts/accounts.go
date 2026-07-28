package accounts

import (
	"context"
	"time"

	"github.com/latebit-io/an/internal/utils"
)

// Account is a user account. Password and verification hashes never leave
// the service layer.
type Account struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenantId"`
	Email    string    `json:"email"`
	Name     string    `json:"name,omitempty"`
	Verified bool      `json:"verified"`
	Enabled  bool      `json:"enabled"`
	Deleted  bool      `json:"deleted"`
	Created  time.Time `json:"created"`
	Modified time.Time `json:"modified"`

	PasswordHash     string `json:"-"`
	VerificationHash string `json:"-"`
}

// RegisteredAccount carries the one-time verification token minted at
// registration; the caller delivers it (an sends no email).
type RegisteredAccount struct {
	Account
	VerificationToken string `json:"verificationToken"`
}

// ResetToken carries a one-time password reset token; the caller delivers it.
type ResetToken struct {
	Token   string    `json:"resetToken"`
	Expires time.Time `json:"expires"`
}

// SessionRevoker revokes all of an account's sessions; implemented by the
// authn session repository and by the OIDC session revoker, both wired in
// main (consumer-side interface). There is more than one because an account
// can be signed in on more than one surface, and a credential change has to
// end all of them or it has ended none of them.
type SessionRevoker interface {
	DeleteAll(ctx context.Context, tenantID, email string) error
}

// LockoutClearer clears an account's failed logon attempts; implemented by
// the authn failed attempt repository and wired in main.
type LockoutClearer interface {
	Clear(ctx context.Context, tenantID, email string) error
}

type AccountService interface {
	// Register takes an optional display name; it is the source of the
	// OIDC name claim and is omitted from the id_token when empty.
	Register(ctx context.Context, tenantID, email, password, name string) (*RegisteredAccount, error)
	UpdateName(ctx context.Context, tenantID, email, name string) error
	Verify(ctx context.Context, tenantID, email, token string) error
	ResendVerification(ctx context.Context, tenantID, email string) (string, error)
	Forgot(ctx context.Context, tenantID, email string) (*ResetToken, error)
	Reset(ctx context.Context, tenantID, email, token, newPassword string) error
	UpdatePassword(ctx context.Context, tenantID, email, currentPassword, newPassword string) error
	Delete(ctx context.Context, tenantID, email string) error
}

type DefaultAccountService struct {
	accounts     AccountRepository
	resets       PasswordResetRepository
	sessions     []SessionRevoker
	lockouts     LockoutClearer
	txManager    utils.TxManager
	passwordCost int
	resetExpiry  time.Duration
}

func NewDefaultAccountService(accounts AccountRepository, resets PasswordResetRepository,
	sessions []SessionRevoker, lockouts LockoutClearer, txManager utils.TxManager,
	passwordCost int, resetExpiry time.Duration) AccountService {
	return &DefaultAccountService{
		accounts:     accounts,
		resets:       resets,
		sessions:     sessions,
		lockouts:     lockouts,
		txManager:    txManager,
		passwordCost: passwordCost,
		resetExpiry:  resetExpiry,
	}
}

func (s *DefaultAccountService) Register(ctx context.Context, tenantID, email, password,
	name string) (*RegisteredAccount, error) {
	if err := utils.ValidateEmail(email); err != nil {
		return nil, InvalidAccountError{Value: err.Error()}
	}
	if err := utils.ValidateName(name); err != nil {
		return nil, InvalidAccountError{Value: err.Error()}
	}
	if err := utils.ValidatePassword(password); err != nil {
		return nil, InvalidAccountError{Value: err.Error()}
	}
	passwordHash, err := utils.BcryptHash(password, s.passwordCost)
	if err != nil {
		return nil, err
	}
	verificationToken, err := utils.RandomToken()
	if err != nil {
		return nil, err
	}
	account, err := s.accounts.Create(ctx, Account{
		TenantID:         tenantID,
		Email:            email,
		Name:             name,
		PasswordHash:     passwordHash,
		VerificationHash: utils.Sha256Hex(verificationToken),
	})
	if err != nil {
		return nil, err
	}
	registered := &RegisteredAccount{Account: *account, VerificationToken: verificationToken}
	registered.PasswordHash = ""
	registered.VerificationHash = ""
	return registered, nil
}

func (s *DefaultAccountService) Verify(ctx context.Context, tenantID, email, token string) error {
	account, err := s.readLive(ctx, tenantID, email)
	if err != nil {
		return err
	}
	if account.Verified {
		return VerificationError{Value: "account already verified"}
	}
	if account.VerificationHash == "" ||
		!utils.SafeCompare(utils.Sha256Hex(token), account.VerificationHash) {
		return VerificationError{Value: "wrong verification token"}
	}
	return s.accounts.SetVerified(ctx, tenantID, email)
}

func (s *DefaultAccountService) ResendVerification(ctx context.Context, tenantID,
	email string) (string, error) {
	account, err := s.readLive(ctx, tenantID, email)
	if err != nil {
		return "", err
	}
	if account.Verified {
		return "", VerificationError{Value: "account already verified"}
	}
	verificationToken, err := utils.RandomToken()
	if err != nil {
		return "", err
	}
	if err := s.accounts.UpdateVerificationHash(ctx, tenantID, email,
		utils.Sha256Hex(verificationToken)); err != nil {
		return "", err
	}
	return verificationToken, nil
}

func (s *DefaultAccountService) Forgot(ctx context.Context, tenantID, email string) (*ResetToken, error) {
	if _, err := s.readLive(ctx, tenantID, email); err != nil {
		return nil, err
	}
	token, err := utils.RandomToken()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(s.resetExpiry)
	if err := s.resets.Upsert(ctx, tenantID, email, utils.Sha256Hex(token), expires); err != nil {
		return nil, err
	}
	return &ResetToken{Token: token, Expires: expires}, nil
}

func (s *DefaultAccountService) Reset(ctx context.Context, tenantID, email, token,
	newPassword string) error {
	if err := utils.ValidatePassword(newPassword); err != nil {
		return InvalidAccountError{Value: err.Error()}
	}
	if _, err := s.readLive(ctx, tenantID, email); err != nil {
		return err
	}
	tokenHash, err := s.resets.Read(ctx, tenantID, email)
	if err != nil {
		return err
	}
	if !utils.SafeCompare(utils.Sha256Hex(token), tokenHash) {
		return ResetTokenInvalidError{}
	}
	passwordHash, err := utils.BcryptHash(newPassword, s.passwordCost)
	if err != nil {
		return err
	}
	// One transaction: a reset that changed the password but left live
	// sessions (or the lockout) behind would be worse than failing whole.
	return s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.accounts.UpdatePasswordHash(ctx, tenantID, email, passwordHash); err != nil {
			return err
		}
		if err := s.resets.Delete(ctx, tenantID, email); err != nil {
			return err
		}
		if err := s.revokeSessions(ctx, tenantID, email); err != nil {
			return err
		}
		return s.lockouts.Clear(ctx, tenantID, email)
	})
}

// UpdateName sets the display name behind the OIDC name claim. An empty
// name clears it, which drops the claim rather than asserting it empty.
func (s *DefaultAccountService) UpdateName(ctx context.Context, tenantID, email, name string) error {
	if err := utils.ValidateName(name); err != nil {
		return InvalidAccountError{Value: err.Error()}
	}
	if _, err := s.readLive(ctx, tenantID, email); err != nil {
		return err
	}
	return s.accounts.UpdateName(ctx, tenantID, email, name)
}

func (s *DefaultAccountService) UpdatePassword(ctx context.Context, tenantID, email,
	currentPassword, newPassword string) error {
	if err := utils.ValidatePassword(newPassword); err != nil {
		return InvalidAccountError{Value: err.Error()}
	}
	account, err := s.readLive(ctx, tenantID, email)
	if err != nil {
		return err
	}
	match, err := utils.BcryptVerify(account.PasswordHash, currentPassword)
	if err != nil {
		return err
	}
	if !match {
		return InvalidAccountError{Value: "wrong password"}
	}
	passwordHash, err := utils.BcryptHash(newPassword, s.passwordCost)
	if err != nil {
		return err
	}
	// One transaction, for the same reason a reset is one: a password that
	// changed while the sessions opened under the old one stayed live has
	// not really changed.
	return s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.accounts.UpdatePasswordHash(ctx, tenantID, email, passwordHash); err != nil {
			return err
		}
		return s.revokeSessions(ctx, tenantID, email)
	})
}

// revokeSessions ends the account's sessions on every surface. One failure
// fails the whole change: a partially revoked account is one the user
// believes they have secured.
func (s *DefaultAccountService) revokeSessions(ctx context.Context, tenantID, email string) error {
	for _, revoker := range s.sessions {
		if err := revoker.DeleteAll(ctx, tenantID, email); err != nil {
			return err
		}
	}
	return nil
}

func (s *DefaultAccountService) Delete(ctx context.Context, tenantID, email string) error {
	if _, err := s.readLive(ctx, tenantID, email); err != nil {
		return err
	}
	return s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.accounts.SoftDelete(ctx, tenantID, email); err != nil {
			return err
		}
		return s.revokeSessions(ctx, tenantID, email)
	})
}

// readLive returns the account unless it is deleted (deleted reads as not
// found).
func (s *DefaultAccountService) readLive(ctx context.Context, tenantID, email string) (*Account, error) {
	account, err := s.accounts.Read(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}
	if account.Deleted {
		return nil, AccountNotFoundError{Value: email}
	}
	return account, nil
}
