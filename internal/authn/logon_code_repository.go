package authn

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

type LogonCodeRepository interface {
	Upsert(ctx context.Context, tenantID, email, codeHash string, expires time.Time) error
	// Read returns the stored code hash; an expired row reads as
	// LogonCodeExpiredError (expiry is enforced, never advisory).
	Read(ctx context.Context, tenantID, email string) (string, error)
	Delete(ctx context.Context, tenantID, email string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

type PostgresLogonCodeRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresLogonCodeRepository(pool *pgxpool.Pool) LogonCodeRepository {
	return &PostgresLogonCodeRepository{pool: pool}
}

func (r *PostgresLogonCodeRepository) Upsert(ctx context.Context, tenantID, email,
	codeHash string, expires time.Time) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		`INSERT INTO logon_codes (tenant_id, email, code_hash, expires)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, email) DO UPDATE SET code_hash = $3, expires = $4, created = now()`,
		tenantID, email, codeHash, expires)
	return err
}

func (r *PostgresLogonCodeRepository) Read(ctx context.Context, tenantID, email string) (string, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var codeHash string
	var expires time.Time
	err := querier.QueryRow(ctx,
		"SELECT code_hash, expires FROM logon_codes WHERE tenant_id = $1 AND email = $2",
		tenantID, email).Scan(&codeHash, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", LogonCodeInvalidError{}
	}
	if err != nil {
		return "", err
	}
	if time.Now().After(expires) {
		return "", LogonCodeExpiredError{}
	}
	return codeHash, nil
}

func (r *PostgresLogonCodeRepository) Delete(ctx context.Context, tenantID, email string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		"DELETE FROM logon_codes WHERE tenant_id = $1 AND email = $2", tenantID, email)
	return err
}

func (r *PostgresLogonCodeRepository) DeleteExpired(ctx context.Context) (int64, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, "DELETE FROM logon_codes WHERE expires < now()")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
