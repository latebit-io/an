package authn

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

// Session tracks an acknowledged token pair for one client of one account.
// Only the latest refresh token (by jti) can renew it.
type Session struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenantId"`
	Email      string    `json:"email"`
	ClientID   string    `json:"clientId"`
	RefreshJTI string    `json:"-"`
	Expires    time.Time `json:"expires"`
	Created    time.Time `json:"created"`
	Modified   time.Time `json:"modified"`
}

type SessionRepository interface {
	Upsert(ctx context.Context, session Session) error
	// Read resolves the exact (tenant, email, client) session — per-client
	// token lifecycle depends on all three keys.
	Read(ctx context.Context, tenantID, email, clientID string) (*Session, error)
	Delete(ctx context.Context, tenantID, email, clientID string) error
	DeleteAll(ctx context.Context, tenantID, email string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

type PostgresSessionRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresSessionRepository(pool *pgxpool.Pool) SessionRepository {
	return &PostgresSessionRepository{pool: pool}
}

func (r *PostgresSessionRepository) Upsert(ctx context.Context, session Session) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = querier.Exec(ctx,
		`INSERT INTO sessions (id, tenant_id, email, client_id, refresh_jti, expires)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, email, client_id)
		 DO UPDATE SET refresh_jti = $5, expires = $6, modified = now()`,
		id.String(), session.TenantID, session.Email, session.ClientID, session.RefreshJTI,
		session.Expires)
	return err
}

func (r *PostgresSessionRepository) Read(ctx context.Context, tenantID, email,
	clientID string) (*Session, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var session Session
	err := querier.QueryRow(ctx,
		`SELECT id, tenant_id, email, client_id, refresh_jti, expires, created, modified
		 FROM sessions WHERE tenant_id = $1 AND email = $2 AND client_id = $3`,
		tenantID, email, clientID).
		Scan(&session.ID, &session.TenantID, &session.Email, &session.ClientID,
			&session.RefreshJTI, &session.Expires, &session.Created, &session.Modified)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *PostgresSessionRepository) Delete(ctx context.Context, tenantID, email, clientID string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx,
		"DELETE FROM sessions WHERE tenant_id = $1 AND email = $2 AND client_id = $3",
		tenantID, email, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return SessionNotFoundError{Value: email + "/" + clientID}
	}
	return nil
}

func (r *PostgresSessionRepository) DeleteAll(ctx context.Context, tenantID, email string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		"DELETE FROM sessions WHERE tenant_id = $1 AND email = $2", tenantID, email)
	return err
}

func (r *PostgresSessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, "DELETE FROM sessions WHERE expires < now()")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
