package tokens

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

type SigningKeyRepository interface {
	Create(ctx context.Context, key SigningKey) error
	ReadAll(ctx context.Context) ([]SigningKey, error)
	ReadLatest(ctx context.Context) (*SigningKey, error)
}

type PostgresSigningKeyRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresSigningKeyRepository(pool *pgxpool.Pool) SigningKeyRepository {
	return &PostgresSigningKeyRepository{pool: pool}
}

func (r *PostgresSigningKeyRepository) Create(ctx context.Context, key SigningKey) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		"INSERT INTO signing_keys (id, algorithm, private_key_pem, public_key_pem) VALUES ($1, $2, $3, $4)",
		key.Kid, key.Algorithm, key.PrivateKeyPEM, key.PublicKeyPEM)
	return err
}

func (r *PostgresSigningKeyRepository) ReadAll(ctx context.Context) ([]SigningKey, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	rows, err := querier.Query(ctx,
		"SELECT id, algorithm, private_key_pem, public_key_pem, created FROM signing_keys ORDER BY created")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []SigningKey{}
	for rows.Next() {
		var key SigningKey
		if err := rows.Scan(&key.Kid, &key.Algorithm, &key.PrivateKeyPEM, &key.PublicKeyPEM, &key.Created); err != nil {
			return keys, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *PostgresSigningKeyRepository) ReadLatest(ctx context.Context) (*SigningKey, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var key SigningKey
	err := querier.QueryRow(ctx,
		"SELECT id, algorithm, private_key_pem, public_key_pem, created FROM signing_keys ORDER BY created DESC LIMIT 1").
		Scan(&key.Kid, &key.Algorithm, &key.PrivateKeyPEM, &key.PublicKeyPEM, &key.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, NoSigningKeyError{}
	}
	if err != nil {
		return nil, err
	}
	return &key, nil
}
