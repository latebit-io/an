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

type BrowserSessionRepository interface {
	// Create stores a session and returns the plaintext cookie value; only
	// its sha256 hash is persisted.
	Create(ctx context.Context, session BrowserSession) (*BrowserSession, string, error)
	Read(ctx context.Context, tenantID, token string) (*BrowserSession, error)
	Delete(ctx context.Context, tenantID, token string) error
	// DeleteAll ends every browser session of one account.
	DeleteAll(ctx context.Context, tenantID, accountID string) error
	// DeleteAllForEmail ends them keyed by email instead, which is how the
	// accounts service names an account when a credential changes.
	DeleteAllForEmail(ctx context.Context, tenantID, email string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

type PostgresBrowserSessionRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresBrowserSessionRepository(pool *pgxpool.Pool) BrowserSessionRepository {
	return &PostgresBrowserSessionRepository{pool: pool}
}

func (r *PostgresBrowserSessionRepository) Create(ctx context.Context,
	session BrowserSession) (*BrowserSession, string, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	id, err := uuid.NewV7()
	if err != nil {
		return nil, "", err
	}
	plaintext, err := utils.RandomToken()
	if err != nil {
		return nil, "", err
	}
	session.ID = id.String()
	err = querier.QueryRow(ctx,
		`INSERT INTO oidc_browser_sessions (id, token_hash, tenant_id, account_id, auth_time, expires)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING created`,
		session.ID, utils.Sha256Hex(plaintext), session.TenantID, session.AccountID,
		session.AuthTime, session.Expires).Scan(&session.Created)
	if err != nil {
		return nil, "", err
	}
	return &session, plaintext, nil
}

// Read resolves a cookie to a live session. Expiry is enforced here, not
// only stored.
func (r *PostgresBrowserSessionRepository) Read(ctx context.Context, tenantID,
	token string) (*BrowserSession, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var session BrowserSession
	err := querier.QueryRow(ctx,
		`SELECT id, tenant_id, account_id, auth_time, expires, created
		 FROM oidc_browser_sessions WHERE token_hash = $1`, utils.Sha256Hex(token)).
		Scan(&session.ID, &session.TenantID, &session.AccountID, &session.AuthTime,
			&session.Expires, &session.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, BrowserSessionNotFoundError{}
	}
	if err != nil {
		return nil, err
	}
	if session.TenantID != tenantID {
		return nil, TenantMismatchError{}
	}
	if session.Expires.Before(time.Now()) {
		return nil, BrowserSessionNotFoundError{}
	}
	return &session, nil
}

func (r *PostgresBrowserSessionRepository) Delete(ctx context.Context, tenantID,
	token string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx,
		"DELETE FROM oidc_browser_sessions WHERE tenant_id = $1 AND token_hash = $2",
		tenantID, utils.Sha256Hex(token))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return BrowserSessionNotFoundError{}
	}
	return nil
}

func (r *PostgresBrowserSessionRepository) DeleteAll(ctx context.Context, tenantID,
	accountID string) error {
	if _, err := uuid.Parse(accountID); err != nil {
		return BrowserSessionNotFoundError{}
	}
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		"DELETE FROM oidc_browser_sessions WHERE tenant_id = $1 AND account_id = $2",
		tenantID, accountID)
	return err
}

// DeleteAllForEmail resolves the account inside the statement: browser
// sessions are keyed by account id, while the accounts service works in
// emails, and a round trip to translate would be a second failure point in
// the middle of a credential change.
func (r *PostgresBrowserSessionRepository) DeleteAllForEmail(ctx context.Context, tenantID,
	email string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		`DELETE FROM oidc_browser_sessions
		 WHERE tenant_id = $1
		   AND account_id IN (SELECT id FROM accounts WHERE tenant_id = $1 AND email = $2)`,
		tenantID, email)
	return err
}

func (r *PostgresBrowserSessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, "DELETE FROM oidc_browser_sessions WHERE expires < now()")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
