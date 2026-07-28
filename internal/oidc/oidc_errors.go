package oidc

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// Postgres constraint codes mapped to typed errors, as every other
// repository here does.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

// DuplicateError is a unique constraint violation: a code, token hash or
// session cookie that already exists.
type DuplicateError struct {
	Value string
}

func (e DuplicateError) Error() string {
	return fmt.Sprintf("already exists: %s", e.Value)
}

// ReferenceError is a foreign key violation: a row pointing at an account
// or grant that is not there.
type ReferenceError struct {
	Value string
}

func (e ReferenceError) Error() string {
	return fmt.Sprintf("referenced row does not exist: %s", e.Value)
}

// constraintError maps a postgres constraint violation onto a typed error
// so callers never see a raw driver error, and problem details never carry
// its text. Anything else passes through untouched.
func constraintError(err error, what string) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case pgUniqueViolation:
		return DuplicateError{Value: what}
	case pgForeignKeyViolation:
		return ReferenceError{Value: what}
	}
	return err
}

// AuthRequestNotFoundError is returned for an unknown, already exchanged or
// expired authorization request. The token endpoint deletes the request on
// a successful exchange, so a replayed code lands here.
type AuthRequestNotFoundError struct {
	Value string
}

func (e AuthRequestNotFoundError) Error() string {
	return fmt.Sprintf("auth request not found: %s", e.Value)
}

// TokenNotFoundError is returned for an unknown, revoked or expired access
// or refresh token.
type TokenNotFoundError struct {
	Value string
}

func (e TokenNotFoundError) Error() string {
	return fmt.Sprintf("token not found: %s", e.Value)
}

// BrowserSessionNotFoundError is returned when the single sign-on cookie
// resolves to no live session.
type BrowserSessionNotFoundError struct{}

func (e BrowserSessionNotFoundError) Error() string {
	return "browser session not found"
}

// ClientNotFoundError is returned for an unregistered client id.
type ClientNotFoundError struct {
	Value string
}

func (e ClientNotFoundError) Error() string {
	return fmt.Sprintf("oidc client not found: %s", e.Value)
}

// RedirectURINotAllowedError is returned when logout is asked to send a
// browser somewhere the client never registered.
type RedirectURINotAllowedError struct {
	Value string
}

func (e RedirectURINotAllowedError) Error() string {
	return fmt.Sprintf("redirect uri not allowed: %s", e.Value)
}

// ClientNotFirstPartyError is returned for a client that is not first
// party. Consent is not implemented, so such a client cannot be served.
type ClientNotFirstPartyError struct {
	Value string
}

func (e ClientNotFirstPartyError) Error() string {
	return fmt.Sprintf("oidc client is not first party: %s", e.Value)
}

// ClientAuthenticationError is returned when a client presents the wrong
// secret at the token endpoint.
type ClientAuthenticationError struct{}

func (e ClientAuthenticationError) Error() string {
	return "client authentication failed"
}

// TenantMismatchError is returned when an authorization request, code or
// token is presented to a tenant other than the one that issued it. The
// library's storage interface carries no tenant, so this is checked here.
type TenantMismatchError struct{}

func (e TenantMismatchError) Error() string {
	return "resource belongs to another tenant"
}

// MissingTenantError is returned when the tenant never made it into the
// request context, which means the provider was mounted without the tenant
// middleware.
type MissingTenantError struct{}

func (e MissingTenantError) Error() string {
	return "no tenant in context"
}
