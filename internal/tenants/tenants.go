package tenants

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/utils"
)

type TenantNotFoundError struct {
	Value string `json:"value"`
}

func (e TenantNotFoundError) Error() string {
	return fmt.Sprintf("tenant not found: %s", e.Value)
}

type Tenant struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	Modified time.Time `json:"modified"`
}

type TenantRepository interface {
	ReadAll(ctx context.Context) ([]Tenant, error)
	Read(ctx context.Context, tenantID string) (*Tenant, error)
	Create(ctx context.Context) error
}

type TenantService interface {
	ListTenants(ctx context.Context) ([]Tenant, error)
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	CreateDefault(ctx context.Context) error
}

type PostgresTenantRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresTenantRepository(pool *pgxpool.Pool) TenantRepository {
	return &PostgresTenantRepository{
		pool: pool,
	}
}

func (t *PostgresTenantRepository) ReadAll(ctx context.Context) ([]Tenant, error) {
	querier := utils.QuerierFrom(ctx, t.pool)
	rows, err := querier.Query(ctx, "SELECT id, name, created, modified FROM tenants")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tenants := []Tenant{}
	for rows.Next() {
		var tenant Tenant
		if err := rows.Scan(&tenant.ID, &tenant.Name, &tenant.Created, &tenant.Modified); err != nil {
			return tenants, err
		}
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}

func (t *PostgresTenantRepository) Read(ctx context.Context, tenantID string) (*Tenant, error) {
	querier := utils.QuerierFrom(ctx, t.pool)
	var tenant Tenant
	err := querier.QueryRow(ctx, "SELECT id, name, created, modified FROM tenants WHERE id = $1",
		tenantID).Scan(&tenant.ID, &tenant.Name, &tenant.Created, &tenant.Modified)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, TenantNotFoundError{Value: tenantID}
	}
	if err != nil {
		return nil, err
	}
	return &tenant, nil
}

func (t *PostgresTenantRepository) Create(ctx context.Context) error {
	querier := utils.QuerierFrom(ctx, t.pool)
	_, err := querier.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", "default", "default")
	return err
}

type DefaultTenantService struct {
	repo TenantRepository
}

func NewDefaultTenantService(repo TenantRepository) TenantService {
	return &DefaultTenantService{
		repo: repo,
	}
}

func (s *DefaultTenantService) ListTenants(ctx context.Context) ([]Tenant, error) {
	return s.repo.ReadAll(ctx)
}

func (s *DefaultTenantService) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	return s.repo.Read(ctx, tenantID)
}

func (s *DefaultTenantService) CreateDefault(ctx context.Context) error {
	return s.repo.Create(ctx)
}
