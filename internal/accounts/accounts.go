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
// authn session repository and wired in main (consumer-side interface).
type SessionRevoker interface {
	DeleteAll(ctx context.Context, tenantID, email string) error
}

// LockoutClearer clears an account's failed logon attempts; implemented by
// the authn failed attempt repository and wired in main.
type LockoutClearer interface {
	Clear(ctx context.Context, tenantID, email string) error
}

type AccountService interface {
	Register(ctx context.Context, tenantID, email, password string) (*RegisteredAccount, error)
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
	sessions     SessionRevoker
	lockouts     LockoutClearer
	txManager    utils.TxManager
	passwordCost int
	resetExpiry  time.Duration
}

func NewDefaultAccountService(accounts AccountRepository, resets PasswordResetRepository,
	sessions SessionRevoker, lockouts LockoutClearer, txManager utils.TxManager,
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

func (s *DefaultAccountService) Register(ctx context.Context, tenantID, email,
	password string) (*RegisteredAccount, error) {
	if err := utils.ValidateEmail(email); err != nil {
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
	err = s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.accounts.UpdatePasswordHash(ctx, tenantID, email, passwordHash); err != nil {
			return err
		}
		return s.resets.Delete(ctx, tenantID, email)
	})
	if err != nil {
		return err
	}
	if err := s.sessions.DeleteAll(ctx, tenantID, email); err != nil {
		return err
	}
	return s.lockouts.Clear(ctx, tenantID, email)
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
	return s.accounts.UpdatePasswordHash(ctx, tenantID, email, passwordHash)
}

func (s *DefaultAccountService) Delete(ctx context.Context, tenantID, email string) error {
	if _, err := s.readLive(ctx, tenantID, email); err != nil {
		return err
	}
	if err := s.accounts.SoftDelete(ctx, tenantID, email); err != nil {
		return err
	}
	return s.sessions.DeleteAll(ctx, tenantID, email)
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
