package social

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

const pgUniqueViolation = "23505"

type SocialRepository interface {
	// Link ties a provider identity to an account; re-linking the same
	// account and provider updates the subject (the provider re-issued
	// the identity for the same email).
	Link(ctx context.Context, accountID, provider, subject string) error
}

type PostgresSocialRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresSocialRepository(pool *pgxpool.Pool) SocialRepository {
	return &PostgresSocialRepository{pool: pool}
}

func (r *PostgresSocialRepository) Link(ctx context.Context, accountID, provider, subject string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	_, err := querier.Exec(ctx,
		`INSERT INTO social_logins (account_id, provider, subject)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (account_id, provider) DO UPDATE SET subject = $3`,
		accountID, provider, subject)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return SocialAlreadyLinkedError{Value: provider}
	}
	return err
}
