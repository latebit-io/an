package apikeys

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

type ApiKeyRepository interface {
	Create(ctx context.Context, key ApiKey, hash string) (*ApiKey, error)
	ReadAll(ctx context.Context, tenantID string) ([]ApiKey, error)
	// ReadByPrefix returns the tenant and stored hash for a token prefix —
	// the authentication hot path.
	ReadByPrefix(ctx context.Context, prefix string) (string, string, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type PostgresApiKeyRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresApiKeyRepository(pool *pgxpool.Pool) ApiKeyRepository {
	return &PostgresApiKeyRepository{pool: pool}
}

func (r *PostgresApiKeyRepository) Create(ctx context.Context, key ApiKey, hash string) (*ApiKey, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	key.ID = id.String()
	err = querier.QueryRow(ctx,
		"INSERT INTO api_keys (id, tenant_id, name, prefix, hash) VALUES ($1, $2, $3, $4, $5) RETURNING created",
		key.ID, key.TenantID, key.Name, key.Prefix, hash).Scan(&key.Created)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return nil, ApiKeyDuplicateError{Value: key.Name}
	}
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *PostgresApiKeyRepository) ReadAll(ctx context.Context, tenantID string) ([]ApiKey, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	rows, err := querier.Query(ctx,
		"SELECT id, tenant_id, name, prefix, created FROM api_keys WHERE tenant_id = $1 ORDER BY name", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []ApiKey{}
	for rows.Next() {
		var key ApiKey
		if err := rows.Scan(&key.ID, &key.TenantID, &key.Name, &key.Prefix, &key.Created); err != nil {
			return keys, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *PostgresApiKeyRepository) ReadByPrefix(ctx context.Context, prefix string) (string, string, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var tenantID, hash string
	err := querier.QueryRow(ctx, "SELECT tenant_id, hash FROM api_keys WHERE prefix = $1", prefix).
		Scan(&tenantID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", InvalidApiKeyError{}
	}
	if err != nil {
		return "", "", err
	}
	return tenantID, hash, nil
}

func (r *PostgresApiKeyRepository) Delete(ctx context.Context, tenantID, id string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, "DELETE FROM api_keys WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ApiKeyNotFoundError{Value: id}
	}
	return nil
}
