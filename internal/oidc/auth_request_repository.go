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

type AuthRequestRepository interface {
	Create(ctx context.Context, request AuthRequest) (*AuthRequest, error)
	Read(ctx context.Context, tenantID, id string) (*AuthRequest, error)
	// ReadByCode resolves a request by its authorization code. The code is
	// stored as a sha256 hash like every other high-entropy token here.
	ReadByCode(ctx context.Context, tenantID, code string) (*AuthRequest, error)
	// Authenticate marks the request done for a subject once the login UI
	// has authenticated the user.
	Authenticate(ctx context.Context, tenantID, id, subject string, authTime time.Time,
		amr []string) error
	SaveCode(ctx context.Context, tenantID, id, code string) error
	Delete(ctx context.Context, tenantID, id string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

type PostgresAuthRequestRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresAuthRequestRepository(pool *pgxpool.Pool) AuthRequestRepository {
	return &PostgresAuthRequestRepository{pool: pool}
}

func (r *PostgresAuthRequestRepository) Create(ctx context.Context,
	request AuthRequest) (*AuthRequest, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	request.ID = id.String()
	err = querier.QueryRow(ctx,
		`INSERT INTO oidc_auth_requests (id, tenant_id, client_id, subject, redirect_uri,
		        response_type, response_mode, scopes, state, nonce, code_challenge,
		        code_challenge_method, amr, auth_time, done, expires)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		 RETURNING created, modified`,
		request.ID, request.TenantID, request.ClientID, request.Subject, request.RedirectURI,
		request.ResponseType, request.ResponseMode, emptyIfNil(request.Scopes), request.State,
		request.Nonce, request.CodeChallenge, request.CodeChallengeMethod, emptyIfNil(request.AMR),
		nullableTime(request.AuthTime), request.Complete, request.Expires).
		Scan(&request.Created, &request.Modified)
	if err != nil {
		return nil, constraintError(err, "auth request")
	}
	return &request, nil
}

func (r *PostgresAuthRequestRepository) Read(ctx context.Context, tenantID,
	id string) (*AuthRequest, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, AuthRequestNotFoundError{Value: id}
	}
	return r.read(ctx, "id = $1", tenantID, id, id)
}

func (r *PostgresAuthRequestRepository) ReadByCode(ctx context.Context, tenantID,
	code string) (*AuthRequest, error) {
	return r.read(ctx, "code_hash = $1", tenantID, utils.Sha256Hex(code), "code")
}

// read loads one request by whichever key the caller selects. Expiry is
// enforced here, not only stored: a stale row reads as a miss.
func (r *PostgresAuthRequestRepository) read(ctx context.Context, predicate, tenantID, key,
	notFound string) (*AuthRequest, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	var request AuthRequest
	var authTime *time.Time
	err := querier.QueryRow(ctx,
		`SELECT id, tenant_id, client_id, subject, redirect_uri, response_type, response_mode,
		        scopes, state, nonce, code_challenge, code_challenge_method, amr, auth_time, done,
		        expires, created, modified
		 FROM oidc_auth_requests WHERE `+predicate, key).
		Scan(&request.ID, &request.TenantID, &request.ClientID, &request.Subject,
			&request.RedirectURI, &request.ResponseType, &request.ResponseMode, &request.Scopes,
			&request.State, &request.Nonce, &request.CodeChallenge, &request.CodeChallengeMethod,
			&request.AMR, &authTime, &request.Complete, &request.Expires, &request.Created,
			&request.Modified)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, AuthRequestNotFoundError{Value: notFound}
	}
	if err != nil {
		return nil, err
	}
	// The tenant is checked after the read rather than in the predicate so
	// a cross-tenant attempt is distinguishable from a plain miss.
	if request.TenantID != tenantID {
		return nil, TenantMismatchError{}
	}
	if request.Expires.Before(time.Now()) {
		return nil, AuthRequestNotFoundError{Value: notFound}
	}
	if authTime != nil {
		request.AuthTime = *authTime
	}
	return &request, nil
}

func (r *PostgresAuthRequestRepository) Authenticate(ctx context.Context, tenantID, id,
	subject string, authTime time.Time, amr []string) error {
	return r.update(ctx,
		`UPDATE oidc_auth_requests SET subject = $3, auth_time = $4, amr = $5, done = true,
		        modified = now()
		 WHERE tenant_id = $1 AND id = $2`, tenantID, id, subject, authTime, emptyIfNil(amr))
}

func (r *PostgresAuthRequestRepository) SaveCode(ctx context.Context, tenantID, id,
	code string) error {
	return r.update(ctx,
		"UPDATE oidc_auth_requests SET code_hash = $3, modified = now() WHERE tenant_id = $1 AND id = $2",
		tenantID, id, utils.Sha256Hex(code))
}

// Delete removes the request. The token endpoint calls it after a
// successful exchange, which is what makes an authorization code
// single-use: a replay finds nothing.
func (r *PostgresAuthRequestRepository) Delete(ctx context.Context, tenantID, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return AuthRequestNotFoundError{Value: id}
	}
	return r.update(ctx,
		"DELETE FROM oidc_auth_requests WHERE tenant_id = $1 AND id = $2", tenantID, id)
}

func (r *PostgresAuthRequestRepository) DeleteExpired(ctx context.Context) (int64, error) {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, "DELETE FROM oidc_auth_requests WHERE expires < now()")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *PostgresAuthRequestRepository) update(ctx context.Context, sql, tenantID, id string,
	args ...any) error {
	querier := utils.QuerierFrom(ctx, r.pool)
	tag, err := querier.Exec(ctx, sql, append([]any{tenantID, id}, args...)...)
	if err != nil {
		return constraintError(err, "auth request")
	}
	if tag.RowsAffected() == 0 {
		return AuthRequestNotFoundError{Value: id}
	}
	return nil
}

// nullableTime keeps an unset time NULL rather than the zero instant.
func nullableTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}
