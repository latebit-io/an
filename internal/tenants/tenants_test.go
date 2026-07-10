package tenants

import (
	"context"
	"os"
	"testing"

	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(utils.RunTestMain(m))
}

func TestTenantService(t *testing.T) {
	pool := utils.NewTestPool(t)
	service := NewDefaultTenantService(NewPostgresTenantRepository(pool))
	ctx := context.Background()

	existing, err := service.ListTenants(ctx)
	require.NoError(t, err)
	assert.Empty(t, existing)

	err = service.CreateDefault(ctx)
	require.NoError(t, err)

	tenant, err := service.GetTenant(ctx, "default")
	require.NoError(t, err)
	assert.Equal(t, "default", tenant.ID)
	assert.Equal(t, "default", tenant.Name)

	all, err := service.ListTenants(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)
}
