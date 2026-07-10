package authn

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/tokens"
	"github.com/latebit-io/an/internal/utils"
)

// Authenticated is an issued access/refresh token pair. It is inert to
// validate and renew until the client acknowledges it.
type Authenticated struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type AuthenticationService interface {
	Authenticate(ctx context.Context, tenantID, email, clientID, password string) (*Authenticated, error)
	Acknowledge(ctx context.Context, tenantID string, authenticated Authenticated) error
	Validate(ctx context.Context, tenantID, accessToken string) (*tokens.AccessClaims, error)
	Renew(ctx context.Context, tenantID, refreshToken string) (*Authenticated, error)
	// Revoke deletes the session for one client, or every session of the
	// account when clientID is empty.
	Revoke(ctx context.Context, tenantID, email, clientID string) error
}

type DefaultAuthenticationService struct {
	accounts        accounts.AccountRepository
	sessions        SessionRepository
	attempts        FailedAttemptRepository
	tokenizer       tokens.Tokenizer
	maxAttempts     int
	lockoutDuration time.Duration
}

func NewDefaultAuthenticationService(accountRepository accounts.AccountRepository,
	sessions SessionRepository, attempts FailedAttemptRepository, tokenizer tokens.Tokenizer,
	maxAttempts int, lockoutDuration time.Duration) *DefaultAuthenticationService {
	return &DefaultAuthenticationService{
		accounts:        accountRepository,
		sessions:        sessions,
		attempts:        attempts,
		tokenizer:       tokenizer,
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
	}
}

func (s *DefaultAuthenticationService) Authenticate(ctx context.Context, tenantID, email, clientID,
	password string) (*Authenticated, error) {
	account, err := s.gateLogon(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}
	match, err := utils.BcryptVerify(account.PasswordHash, password)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, s.countFailure(ctx, tenantID, email)
	}
	if err := s.attempts.Clear(ctx, tenantID, email); err != nil {
		return nil, err
	}
	authenticated, _, err := s.issue(ctx, tenantID, email, clientID)
	return authenticated, err
}

func (s *DefaultAuthenticationService) Acknowledge(ctx context.Context, tenantID string,
	authenticated Authenticated) error {
	accessClaims, err := s.tokenizer.ValidateAccessToken(ctx, authenticated.AccessToken)
	if err != nil {
		return err
	}
	refreshClaims, err := s.tokenizer.ValidateRefreshToken(ctx, authenticated.RefreshToken)
	if err != nil {
		return err
	}
	if accessClaims.TenantID != tenantID || refreshClaims.TenantID != tenantID {
		return TokenTenantMismatchError{}
	}
	if accessClaims.ClientID != refreshClaims.ClientID ||
		accessClaims.Subject != refreshClaims.Subject {
		return tokens.TokenInvalidError{Reason: "access and refresh tokens do not belong together"}
	}
	return s.sessions.Upsert(ctx, Session{
		TenantID:   tenantID,
		Email:      refreshClaims.Subject,
		ClientID:   refreshClaims.ClientID,
		RefreshJTI: refreshClaims.ID,
		Expires:    refreshClaims.ExpiresAt.Time,
	})
}

func (s *DefaultAuthenticationService) Validate(ctx context.Context, tenantID,
	accessToken string) (*tokens.AccessClaims, error) {
	claims, err := s.tokenizer.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if claims.TenantID != tenantID {
		return nil, TokenTenantMismatchError{}
	}
	if _, err := s.readSession(ctx, tenantID, claims.Subject, claims.ClientID); err != nil {
		return nil, err
	}
	return claims, nil
}

func (s *DefaultAuthenticationService) Renew(ctx context.Context, tenantID,
	refreshToken string) (*Authenticated, error) {
	claims, err := s.tokenizer.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if claims.TenantID != tenantID {
		return nil, TokenTenantMismatchError{}
	}
	session, err := s.readSession(ctx, tenantID, claims.Subject, claims.ClientID)
	if err != nil {
		return nil, err
	}
	// Only the latest refresh token renews: a rotated-away or revoked
	// token is dead even though its signature still verifies.
	if !utils.SafeCompare(claims.ID, session.RefreshJTI) {
		return nil, TokenNotAcknowledgedError{}
	}
	if _, err := s.liveAccount(ctx, tenantID, claims.Subject); err != nil {
		return nil, err
	}
	authenticated, refreshClaims, err := s.issue(ctx, tenantID, claims.Subject, claims.ClientID)
	if err != nil {
		return nil, err
	}
	// Rotate the session to the new refresh token; no re-ack needed.
	err = s.sessions.Upsert(ctx, Session{
		TenantID:   tenantID,
		Email:      claims.Subject,
		ClientID:   claims.ClientID,
		RefreshJTI: refreshClaims.ID,
		Expires:    refreshClaims.ExpiresAt.Time,
	})
	if err != nil {
		return nil, err
	}
	return authenticated, nil
}

func (s *DefaultAuthenticationService) Revoke(ctx context.Context, tenantID, email,
	clientID string) error {
	if clientID == "" {
		return s.sessions.DeleteAll(ctx, tenantID, email)
	}
	return s.sessions.Delete(ctx, tenantID, email, clientID)
}

// issue mints a token pair. It does not touch the session store: freshly
// issued tokens stay inert to validate and renew until the client
// acknowledges them (renew rotates the session itself).
func (s *DefaultAuthenticationService) issue(ctx context.Context, tenantID, email,
	clientID string) (*Authenticated, *tokens.RefreshClaims, error) {
	accessToken, _, err := s.tokenizer.CreateAccessToken(ctx, tenantID, email, clientID)
	if err != nil {
		return nil, nil, err
	}
	refreshToken, refreshClaims, err := s.tokenizer.CreateRefreshToken(ctx, tenantID, email, clientID)
	if err != nil {
		return nil, nil, err
	}
	return &Authenticated{AccessToken: accessToken, RefreshToken: refreshToken}, refreshClaims, nil
}

// gateLogon runs the shared pre-logon checks: lockout, account exists, is
// enabled and verified. Unknown accounts fail exactly like wrong passwords.
func (s *DefaultAuthenticationService) gateLogon(ctx context.Context, tenantID,
	email string) (*accounts.Account, error) {
	if err := s.checkLockout(ctx, tenantID, email); err != nil {
		return nil, err
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
	if !account.Verified {
		return nil, accounts.AccountNotVerifiedError{Value: email}
	}
	return account, nil
}

func (s *DefaultAuthenticationService) checkLockout(ctx context.Context, tenantID, email string) error {
	attempt, err := s.attempts.Get(ctx, tenantID, email)
	if err != nil || attempt == nil {
		return err
	}
	if attempt.LockedUntil != nil {
		if attempt.LockedUntil.After(time.Now()) {
			return AccountLockedError{Value: email, LockedUntil: *attempt.LockedUntil}
		}
		// The lock expired: forget the stale attempts so the counter
		// starts fresh instead of re-locking on the next failure.
		return s.attempts.Clear(ctx, tenantID, email)
	}
	return nil
}

// countFailure records a failed logon and reports either the lockout it
// triggered or the generic authentication failure.
func (s *DefaultAuthenticationService) countFailure(ctx context.Context, tenantID, email string) error {
	lockedUntil, err := s.attempts.IncrementAndLock(ctx, tenantID, email, s.maxAttempts,
		s.lockoutDuration)
	if err != nil {
		return err
	}
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		return AccountLockedError{Value: email, LockedUntil: *lockedUntil}
	}
	return AuthenticationError{}
}

func (s *DefaultAuthenticationService) readSession(ctx context.Context, tenantID, email,
	clientID string) (*Session, error) {
	session, err := s.sessions.Read(ctx, tenantID, email, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, TokenNotAcknowledgedError{}
	}
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (s *DefaultAuthenticationService) liveAccount(ctx context.Context, tenantID,
	email string) (*accounts.Account, error) {
	account, err := s.accounts.Read(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}
	if account.Deleted || !account.Enabled {
		return nil, AuthenticationError{}
	}
	return account, nil
}
