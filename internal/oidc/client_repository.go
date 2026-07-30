package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

// RegisteredClient is a client held as data rather than configuration. Same
// shape as StaticClient plus the fields a registry needs to manage one.
type RegisteredClient struct {
	TenantID               string
	ClientID               string
	SecretHash             string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	FirstParty             bool
	Name                   string
	CreatedAt              time.Time
}

// ClientRepository stores clients registered through the admin API.
//
// A registered client is a credential, so the secret is returned once at
// creation and only its hash is kept. There is no read path that returns it:
// an operator who loses it registers another.
type ClientRepository interface {
	// Create stores the client and returns the plaintext secret. The caller
	// hands it to whoever will authenticate with it and does not keep it.
	Create(ctx context.Context, client RegisteredClient) (*RegisteredClient, string, error)
	Read(ctx context.Context, tenantID, clientID string) (*RegisteredClient, error)
	Delete(ctx context.Context, tenantID, clientID string) error
}

type PostgresClientRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresClientRepository(pool *pgxpool.Pool) ClientRepository {
	return &PostgresClientRepository{pool: pool}
}

func (r *PostgresClientRepository) Create(ctx context.Context,
	client RegisteredClient) (*RegisteredClient, string, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	secret, err := utils.RandomToken()
	if err != nil {
		return nil, "", err
	}

	client.SecretHash = utils.Sha256Hex(secret)
	client.CreatedAt = time.Now().UTC()
	// A nil slice is written as NULL, which the column refuses; the column
	// default only applies when the value is left out entirely. Normalised
	// here so a client with no post-logout URIs is not a caller's problem.
	client.RedirectURIs = orEmpty(client.RedirectURIs)
	client.PostLogoutRedirectURIs = orEmpty(client.PostLogoutRedirectURIs)
	_, err = querier.Exec(ctx,
		`INSERT INTO oidc_clients (tenant_id, client_id, secret_hash, redirect_uris,
		    post_logout_redirect_uris, first_party, name, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		client.TenantID, client.ClientID, client.SecretHash, client.RedirectURIs,
		client.PostLogoutRedirectURIs, client.FirstParty, client.Name, client.CreatedAt)
	if err != nil {
		return nil, "", constraintError(err, client.ClientID)
	}
	return &client, secret, nil
}

func orEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func (r *PostgresClientRepository) Read(ctx context.Context,
	tenantID, clientID string) (*RegisteredClient, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var client RegisteredClient
	err := querier.QueryRow(ctx,
		`SELECT tenant_id, client_id, secret_hash, redirect_uris,
		        post_logout_redirect_uris, first_party, name, created_at
		 FROM oidc_clients WHERE tenant_id = $1 AND client_id = $2`,
		tenantID, clientID).Scan(&client.TenantID, &client.ClientID, &client.SecretHash,
		&client.RedirectURIs, &client.PostLogoutRedirectURIs, &client.FirstParty,
		&client.Name, &client.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ClientNotFoundError{Value: clientID}
	}
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (r *PostgresClientRepository) Delete(ctx context.Context, tenantID, clientID string) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx,
		`DELETE FROM oidc_clients WHERE tenant_id = $1 AND client_id = $2`, tenantID, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ClientNotFoundError{Value: clientID}
	}
	return nil
}
