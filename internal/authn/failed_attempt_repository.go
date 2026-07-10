package authn

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

// FailedAttempt tracks failed logon attempts for lockout.
type FailedAttempt struct {
	TenantID    string
	Email       string
	Count       int
	LockedUntil *time.Time
	Modified    time.Time
}

type FailedAttemptRepository interface {
	// Get returns (nil, nil) when no attempts are recorded.
	Get(ctx context.Context, tenantID, email string) (*FailedAttempt, error)
	// IncrementAndLock atomically counts a failure and locks the account
	// once maxAttempts is reached; returns the lock expiry when locked.
	IncrementAndLock(ctx context.Context, tenantID, email string, maxAttempts int,
		lockFor time.Duration) (*time.Time, error)
	Clear(ctx context.Context, tenantID, email string) error
	DeleteStale(ctx context.Context, olderThan time.Duration) (int64, error)
}

type PostgresFailedAttemptRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresFailedAttemptRepository(pool *pgxpool.Pool) FailedAttemptRepository {
	return &PostgresFailedAttemptRepository{pool: pool}
}

func (r *PostgresFailedAttemptRepository) Get(ctx context.Context, tenantID,
	email string) (*FailedAttempt, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var attempt FailedAttempt
	err := querier.QueryRow(ctx,
		"SELECT tenant_id, email, count, locked_until, modified FROM failed_attempts WHERE tenant_id = $1 AND email = $2",
		tenantID, email).
		Scan(&attempt.TenantID, &attempt.Email, &attempt.Count, &attempt.LockedUntil, &attempt.Modified)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &attempt, nil
}

func (r *PostgresFailedAttemptRepository) IncrementAndLock(ctx context.Context, tenantID,
	email string, maxAttempts int, lockFor time.Duration) (*time.Time, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var lockedUntil *time.Time
	err := querier.QueryRow(ctx,
		`INSERT INTO failed_attempts (tenant_id, email, count, locked_until, modified)
		 VALUES ($1, $2, 1, CASE WHEN 1 >= $3 THEN now() + make_interval(secs => $4) END, now())
		 ON CONFLICT (tenant_id, email) DO UPDATE SET
		     count = failed_attempts.count + 1,
		     locked_until = CASE WHEN failed_attempts.count + 1 >= $3
		                         THEN now() + make_interval(secs => $4)
		                         ELSE failed_attempts.locked_until END,
		     modified = now()
		 RETURNING locked_until`,
		tenantID, email, maxAttempts, lockFor.Seconds()).Scan(&lockedUntil)
	if err != nil {
		return nil, err
	}
	return lockedUntil, nil
}

func (r *PostgresFailedAttemptRepository) Clear(ctx context.Context, tenantID, email string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		"DELETE FROM failed_attempts WHERE tenant_id = $1 AND email = $2", tenantID, email)
	return err
}

func (r *PostgresFailedAttemptRepository) DeleteStale(ctx context.Context,
	olderThan time.Duration) (int64, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx,
		"DELETE FROM failed_attempts WHERE modified < now() - make_interval(secs => $1)",
		olderThan.Seconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
