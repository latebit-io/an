package accounts

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

const pgUniqueViolation = "23505"

type AccountRepository interface {
	Create(ctx context.Context, account Account) (*Account, error)
	// CreateVerified creates an account born verified (social sign-in:
	// the provider already asserted the email).
	CreateVerified(ctx context.Context, account Account) (*Account, error)
	Read(ctx context.Context, tenantID, email string) (*Account, error)
	SetVerified(ctx context.Context, tenantID, email string) error
	UpdateVerificationHash(ctx context.Context, tenantID, email, hash string) error
	UpdatePasswordHash(ctx context.Context, tenantID, email, hash string) error
	SoftDelete(ctx context.Context, tenantID, email string) error
}

type PostgresAccountRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresAccountRepository(pool *pgxpool.Pool) AccountRepository {
	return &PostgresAccountRepository{pool: pool}
}

func (r *PostgresAccountRepository) Create(ctx context.Context, account Account) (*Account, error) {
	return r.create(ctx, account, false)
}

func (r *PostgresAccountRepository) CreateVerified(ctx context.Context, account Account) (*Account, error) {
	return r.create(ctx, account, true)
}

func (r *PostgresAccountRepository) create(ctx context.Context, account Account,
	verified bool) (*Account, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	account.ID = id.String()
	account.Verified = verified
	var verificationHash *string
	if !verified {
		verificationHash = &account.VerificationHash
	}
	err = querier.QueryRow(ctx,
		`INSERT INTO accounts (id, tenant_id, email, password_hash, verified, verification_hash)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING enabled, deleted, created, modified`,
		account.ID, account.TenantID, account.Email, account.PasswordHash, verified, verificationHash).
		Scan(&account.Enabled, &account.Deleted, &account.Created, &account.Modified)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return nil, AccountDuplicateError{Value: account.Email}
	}
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *PostgresAccountRepository) Read(ctx context.Context, tenantID, email string) (*Account, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var account Account
	var verificationHash *string
	err := querier.QueryRow(ctx,
		`SELECT id, tenant_id, email, password_hash, verified, verification_hash, enabled, deleted,
		        created, modified
		 FROM accounts WHERE tenant_id = $1 AND email = $2`, tenantID, email).
		Scan(&account.ID, &account.TenantID, &account.Email, &account.PasswordHash, &account.Verified,
			&verificationHash, &account.Enabled, &account.Deleted, &account.Created, &account.Modified)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, AccountNotFoundError{Value: email}
	}
	if err != nil {
		return nil, err
	}
	if verificationHash != nil {
		account.VerificationHash = *verificationHash
	}
	return &account, nil
}

func (r *PostgresAccountRepository) SetVerified(ctx context.Context, tenantID, email string) error {
	return r.update(ctx,
		"UPDATE accounts SET verified = true, verification_hash = NULL, modified = now() WHERE tenant_id = $1 AND email = $2",
		tenantID, email)
}

func (r *PostgresAccountRepository) UpdateVerificationHash(ctx context.Context, tenantID, email,
	hash string) error {
	return r.update(ctx,
		"UPDATE accounts SET verification_hash = $3, modified = now() WHERE tenant_id = $1 AND email = $2",
		tenantID, email, hash)
}

func (r *PostgresAccountRepository) UpdatePasswordHash(ctx context.Context, tenantID, email,
	hash string) error {
	return r.update(ctx,
		"UPDATE accounts SET password_hash = $3, modified = now() WHERE tenant_id = $1 AND email = $2",
		tenantID, email, hash)
}

func (r *PostgresAccountRepository) SoftDelete(ctx context.Context, tenantID, email string) error {
	return r.update(ctx,
		"UPDATE accounts SET deleted = true, modified = now() WHERE tenant_id = $1 AND email = $2",
		tenantID, email)
}

func (r *PostgresAccountRepository) update(ctx context.Context, sql string, tenantID, email string,
	args ...any) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, sql, append([]any{tenantID, email}, args...)...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return AccountNotFoundError{Value: email}
	}
	return nil
}
