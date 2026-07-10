package authn

import "time"

// AuthenticationError is the deliberately generic logon failure: wrong
// password, wrong code, or unknown account — callers cannot tell which.
type AuthenticationError struct{}

func (e AuthenticationError) Error() string {
	return "authentication failed"
}

// AccountLockedError signals too many failed logon attempts.
type AccountLockedError struct {
	Value       string
	LockedUntil time.Time
}

func (e AccountLockedError) Error() string {
	return "account locked until " + e.LockedUntil.Format(time.RFC3339)
}

// TokenNotAcknowledgedError signals a token whose session was never
// acknowledged or has been revoked.
type TokenNotAcknowledgedError struct{}

func (e TokenNotAcknowledgedError) Error() string {
	return "token not acknowledged"
}

// TokenTenantMismatchError signals a token presented against a different
// tenant than it was issued for.
type TokenTenantMismatchError struct{}

func (e TokenTenantMismatchError) Error() string {
	return "token was issued for a different tenant"
}

// LogonCodeInvalidError signals a missing or malformed logon code.
type LogonCodeInvalidError struct{}

func (e LogonCodeInvalidError) Error() string {
	return "invalid logon code"
}

// LogonCodeExpiredError signals an expired logon code.
type LogonCodeExpiredError struct{}

func (e LogonCodeExpiredError) Error() string {
	return "logon code expired"
}

// SessionNotFoundError signals a revoke against a session that does not
// exist.
type SessionNotFoundError struct {
	Value string
}

func (e SessionNotFoundError) Error() string {
	return "session not found: " + e.Value
}
