package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

type TokenRepository interface {
	CreateAccessToken(ctx context.Context, token AccessToken) (*AccessToken, error)
	ReadAccessToken(ctx context.Context, tenantID, id string) (*AccessToken, error)
	DeleteAccessToken(ctx context.Context, tenantID, id string) error

	// CreateRefreshToken stores the grant and returns the plaintext token;
	// only its sha256 hash is persisted.
	CreateRefreshToken(ctx context.Context, token RefreshToken) (*RefreshToken, string, error)
	ReadRefreshToken(ctx context.Context, tenantID, token string) (*RefreshToken, error)
	ReadRefreshTokenByID(ctx context.Context, tenantID, id string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, tenantID, id string) error
	// DeleteGrants drops every grant of one subject at one client, which is
	// what logout and revocation act on.
	DeleteGrants(ctx context.Context, tenantID, subject, clientID string) error
	// DeleteGrantsForEmail drops every grant of one account at every
	// client, which is what a credential change has to do.
	DeleteGrantsForEmail(ctx context.Context, tenantID, email string) error

	DeleteExpired(ctx context.Context) (int64, error)
}

type PostgresTokenRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresTokenRepository(pool *pgxpool.Pool) TokenRepository {
	return &PostgresTokenRepository{pool: pool}
}

func (r *PostgresTokenRepository) CreateAccessToken(ctx context.Context,
	token AccessToken) (*AccessToken, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	token.ID = id.String()
	err = querier.QueryRow(ctx,
		`INSERT INTO oidc_access_tokens (id, tenant_id, client_id, subject, audience, scopes,
		        refresh_token_id, expires)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING created`,
		token.ID, token.TenantID, token.ClientID, token.Subject, emptyIfNil(token.Audience),
		emptyIfNil(token.Scopes), nullableID(token.RefreshTokenID), token.Expires).
		Scan(&token.Created)
	if err != nil {
		return nil, constraintError(err, "access token")
	}
	return &token, nil
}

func (r *PostgresTokenRepository) ReadAccessToken(ctx context.Context, tenantID,
	id string) (*AccessToken, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, TokenNotFoundError{Value: id}
	}
	querier := utils.QuerierFrom(ctx, r.pool)
	var token AccessToken
	// refresh_token_id is written for the cascade, never read back.
	err := querier.QueryRow(ctx,
		`SELECT id, tenant_id, client_id, subject, audience, scopes, expires, created
		 FROM oidc_access_tokens WHERE id = $1`, id).
		Scan(&token.ID, &token.TenantID, &token.ClientID, &token.Subject, &token.Audience,
			&token.Scopes, &token.Expires, &token.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, TokenNotFoundError{Value: id}
	}
	if err != nil {
		return nil, err
	}
	if token.TenantID != tenantID {
		return nil, TenantMismatchError{}
	}
	if token.Expires.Before(time.Now()) {
		return nil, TokenNotFoundError{Value: id}
	}
	return &token, nil
}

func (r *PostgresTokenRepository) DeleteAccessToken(ctx context.Context, tenantID, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return TokenNotFoundError{Value: id}
	}
	return r.exec(ctx, "DELETE FROM oidc_access_tokens WHERE tenant_id = $1 AND id = $2",
		TokenNotFoundError{Value: id}, tenantID, id)
}

func (r *PostgresTokenRepository) CreateRefreshToken(ctx context.Context,
	token RefreshToken) (*RefreshToken, string, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	id, err := uuid.NewV7()
	if err != nil {
		return nil, "", err
	}
	plaintext, err := utils.RandomToken()
	if err != nil {
		return nil, "", err
	}
	token.ID = id.String()
	err = querier.QueryRow(ctx,
		`INSERT INTO oidc_refresh_tokens (id, token_hash, tenant_id, client_id, subject, audience,
		        scopes, amr, auth_time, expires)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING created`,
		token.ID, utils.Sha256Hex(plaintext), token.TenantID, token.ClientID, token.Subject,
		emptyIfNil(token.Audience), emptyIfNil(token.Scopes), emptyIfNil(token.AMR),
		token.AuthTime, token.Expires).Scan(&token.Created)
	if err != nil {
		return nil, "", constraintError(err, "refresh token")
	}
	return &token, plaintext, nil
}

func (r *PostgresTokenRepository) ReadRefreshToken(ctx context.Context, tenantID,
	token string) (*RefreshToken, error) {
	return r.readRefreshToken(ctx, "token_hash = $1", tenantID, utils.Sha256Hex(token), "refresh token")
}

func (r *PostgresTokenRepository) ReadRefreshTokenByID(ctx context.Context, tenantID,
	id string) (*RefreshToken, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, TokenNotFoundError{Value: id}
	}
	return r.readRefreshToken(ctx, "id = $1", tenantID, id, id)
}

func (r *PostgresTokenRepository) readRefreshToken(ctx context.Context, predicate, tenantID, key,
	notFound string) (*RefreshToken, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var token RefreshToken
	err := querier.QueryRow(ctx,
		`SELECT id, tenant_id, client_id, subject, audience, scopes, amr, auth_time, expires, created
		 FROM oidc_refresh_tokens WHERE `+predicate, key).
		Scan(&token.ID, &token.TenantID, &token.ClientID, &token.Subject, &token.Audience,
			&token.Scopes, &token.AMR, &token.AuthTime, &token.Expires, &token.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, TokenNotFoundError{Value: notFound}
	}
	if err != nil {
		return nil, err
	}
	if token.TenantID != tenantID {
		return nil, TenantMismatchError{}
	}
	if token.Expires.Before(time.Now()) {
		return nil, TokenNotFoundError{Value: notFound}
	}
	return &token, nil
}

func (r *PostgresTokenRepository) DeleteRefreshToken(ctx context.Context, tenantID, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return TokenNotFoundError{Value: id}
	}
	return r.exec(ctx, "DELETE FROM oidc_refresh_tokens WHERE tenant_id = $1 AND id = $2",
		TokenNotFoundError{Value: id}, tenantID, id)
}

// DeleteGrants drops every grant of one subject at one client. Access
// tokens cascade from their refresh token; the ones minted without an
// offline_access grant are removed alongside.
func (r *PostgresTokenRepository) DeleteGrants(ctx context.Context, tenantID, subject,
	clientID string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	if _, err := querier.Exec(ctx,
		`DELETE FROM oidc_refresh_tokens WHERE tenant_id = $1 AND subject = $2 AND client_id = $3`,
		tenantID, subject, clientID); err != nil {
		return err
	}
	_, err := querier.Exec(ctx,
		`DELETE FROM oidc_access_tokens WHERE tenant_id = $1 AND subject = $2 AND client_id = $3`,
		tenantID, subject, clientID)
	return err
}

// DeleteGrantsForEmail resolves the account inside the statement. The
// subject of a grant is the account id, so the id is cast to text to match.
func (r *PostgresTokenRepository) DeleteGrantsForEmail(ctx context.Context, tenantID,
	email string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	const subjects = `(SELECT id::text FROM accounts WHERE tenant_id = $1 AND email = $2)`
	if _, err := querier.Exec(ctx,
		`DELETE FROM oidc_refresh_tokens WHERE tenant_id = $1 AND subject IN `+subjects,
		tenantID, email); err != nil {
		return err
	}
	if _, err := querier.Exec(ctx,
		`DELETE FROM oidc_access_tokens WHERE tenant_id = $1 AND subject IN `+subjects,
		tenantID, email); err != nil {
		return err
	}
	// An authorization request already tied to the account would still
	// exchange for a token minted under the old credential.
	_, err := querier.Exec(ctx,
		`DELETE FROM oidc_auth_requests WHERE tenant_id = $1 AND subject IN `+subjects,
		tenantID, email)
	return err
}

func (r *PostgresTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	accessTag, err := querier.Exec(ctx, "DELETE FROM oidc_access_tokens WHERE expires < now()")
	if err != nil {
		return 0, err
	}
	refreshTag, err := querier.Exec(ctx, "DELETE FROM oidc_refresh_tokens WHERE expires < now()")
	if err != nil {
		return accessTag.RowsAffected(), err
	}
	return accessTag.RowsAffected() + refreshTag.RowsAffected(), nil
}

func (r *PostgresTokenRepository) exec(ctx context.Context, sql string, notFound error,
	args ...any) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return notFound
	}
	return nil
}

// emptyIfNil sends an empty array rather than NULL. A column default does
// not apply to an explicitly passed NULL, so a nil slice would otherwise
// violate the NOT NULL constraint.
func emptyIfNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// nullableID keeps an absent foreign key NULL rather than an empty string,
// which would not cast to uuid.
func nullableID(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}
