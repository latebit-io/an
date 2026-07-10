package authn

import (
	"context"
	"errors"
	"time"

	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/utils"
)

const logonCodeLength = 6

// IssuedCode carries a one-time logon code; the caller delivers it (an
// sends no email).
type IssuedCode struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
}

type LogonCodeService interface {
	Request(ctx context.Context, tenantID, email string) (*IssuedCode, error)
	Authenticate(ctx context.Context, tenantID, email, clientID, code string) (*Authenticated, error)
}

type DefaultLogonCodeService struct {
	authentication *DefaultAuthenticationService
	accounts       accounts.AccountRepository
	codes          LogonCodeRepository
	codeExpiry     time.Duration
	bcryptCost     int
}

func NewDefaultLogonCodeService(authentication *DefaultAuthenticationService,
	accountRepository accounts.AccountRepository, codes LogonCodeRepository,
	codeExpiry time.Duration, bcryptCost int) LogonCodeService {
	return &DefaultLogonCodeService{
		authentication: authentication,
		accounts:       accountRepository,
		codes:          codes,
		codeExpiry:     codeExpiry,
		bcryptCost:     bcryptCost,
	}
}

// Request mints a 6-digit logon code for an existing account. Unlike the
// password gate it does not require the account to be verified: proving
// receipt of the code proves mailbox ownership.
func (s *DefaultLogonCodeService) Request(ctx context.Context, tenantID, email string) (*IssuedCode, error) {
	account, err := s.accounts.Read(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}
	if account.Deleted {
		return nil, accounts.AccountNotFoundError{Value: email}
	}
	if !account.Enabled {
		return nil, accounts.AccountDisabledError{Value: email}
	}
	code, err := utils.RandomDigits(logonCodeLength)
	if err != nil {
		return nil, err
	}
	codeHash, err := utils.BcryptHash(code, s.bcryptCost)
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(s.codeExpiry)
	if err := s.codes.Upsert(ctx, tenantID, email, codeHash, expires); err != nil {
		return nil, err
	}
	return &IssuedCode{Code: code, Expires: expires}, nil
}

// Authenticate logs on with a code. Failures count toward the same lockout
// as password logons; success burns the code, clears the lockout and marks
// an unverified account verified (the code reached the mailbox).
func (s *DefaultLogonCodeService) Authenticate(ctx context.Context, tenantID, email, clientID,
	code string) (*Authenticated, error) {
	if err := s.authentication.checkLockout(ctx, tenantID, email); err != nil {
		return nil, err
	}
	if err := utils.ValidateCode(code, logonCodeLength); err != nil {
		return nil, LogonCodeInvalidError{}
	}
	account, err := s.accounts.Read(ctx, tenantID, email)
	var notFound accounts.AccountNotFoundError
	if errors.As(err, &notFound) {
		return nil, AuthenticationError{}
	}
	if err != nil {
		return nil, err
	}
	if account.Deleted {
		return nil, AuthenticationError{}
	}
	if !account.Enabled {
		return nil, accounts.AccountDisabledError{Value: email}
	}
	codeHash, err := s.codes.Read(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}
	match, err := utils.BcryptVerify(codeHash, code)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, s.authentication.countFailure(ctx, tenantID, email)
	}
	if err := s.codes.Delete(ctx, tenantID, email); err != nil {
		return nil, err
	}
	if err := s.authentication.attempts.Clear(ctx, tenantID, email); err != nil {
		return nil, err
	}
	if !account.Verified {
		if err := s.accounts.SetVerified(ctx, tenantID, email); err != nil {
			return nil, err
		}
	}
	authenticated, _, err := s.authentication.issue(ctx, tenantID, email, clientID)
	return authenticated, err
}
