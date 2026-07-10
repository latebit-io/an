package accounts

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

type PasswordResetRepository interface {
	Upsert(ctx context.Context, tenantID, email, tokenHash string, expires time.Time) error
	// Read returns the stored token hash; an expired row reads as
	// ResetTokenExpiredError (expiry is enforced, never advisory).
	Read(ctx context.Context, tenantID, email string) (string, error)
	Delete(ctx context.Context, tenantID, email string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

type PostgresPasswordResetRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresPasswordResetRepository(pool *pgxpool.Pool) PasswordResetRepository {
	return &PostgresPasswordResetRepository{pool: pool}
}

func (r *PostgresPasswordResetRepository) Upsert(ctx context.Context, tenantID, email,
	tokenHash string, expires time.Time) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		`INSERT INTO password_resets (tenant_id, email, token_hash, expires)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, email) DO UPDATE SET token_hash = $3, expires = $4, created = now()`,
		tenantID, email, tokenHash, expires)
	return err
}

func (r *PostgresPasswordResetRepository) Read(ctx context.Context, tenantID, email string) (string, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var tokenHash string
	var expires time.Time
	err := querier.QueryRow(ctx,
		"SELECT token_hash, expires FROM password_resets WHERE tenant_id = $1 AND email = $2",
		tenantID, email).Scan(&tokenHash, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ResetTokenInvalidError{}
	}
	if err != nil {
		return "", err
	}
	if time.Now().After(expires) {
		return "", ResetTokenExpiredError{}
	}
	return tokenHash, nil
}

func (r *PostgresPasswordResetRepository) Delete(ctx context.Context, tenantID, email string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		"DELETE FROM password_resets WHERE tenant_id = $1 AND email = $2", tenantID, email)
	return err
}

func (r *PostgresPasswordResetRepository) DeleteExpired(ctx context.Context) (int64, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, "DELETE FROM password_resets WHERE expires < now()")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
