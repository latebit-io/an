package apikeys

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(utils.RunTestMain(m))
}

func newApiKeyService(t *testing.T) (ApiKeyService, context.Context) {
	pool := utils.NewTestPool(t)
	return NewDefaultApiKeyService(NewPostgresApiKeyRepository(pool)), context.Background()
}

func TestApiKeyService_CreateAndAuthenticate(t *testing.T) {
	service, ctx := newApiKeyService(t)

	created, err := service.Create(ctx, "acme", "backend")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(created.Key, "ank_"))
	assert.Equal(t, created.Key[:12], created.Prefix)
	assert.NotEmpty(t, created.ID)

	tenantID, err := service.Authenticate(ctx, created.Key)
	require.NoError(t, err)
	assert.Equal(t, "acme", tenantID)
}

func TestApiKeyService_AuthenticateRejects(t *testing.T) {
	service, ctx := newApiKeyService(t)

	created, err := service.Create(ctx, "acme", "backend")
	require.NoError(t, err)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"wrong marker", "bwa_" + strings.Repeat("a", 64)},
		{"unknown prefix", "ank_" + strings.Repeat("f", 64)},
		{"right prefix wrong secret", created.Prefix + strings.Repeat("0", 56)},
		{"truncated", created.Key[:20]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Authenticate(ctx, tt.token)
			var invalid InvalidApiKeyError
			assert.ErrorAs(t, err, &invalid)
		})
	}
}

func TestApiKeyService_ListNeverExposesSecrets(t *testing.T) {
	service, ctx := newApiKeyService(t)

	_, err := service.Create(ctx, "acme", "backend")
	require.NoError(t, err)
	_, err = service.Create(ctx, "acme", "frontend")
	require.NoError(t, err)
	_, err = service.Create(ctx, "other", "backend")
	require.NoError(t, err)

	keys, err := service.List(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, keys, 2)
	for _, key := range keys {
		assert.Len(t, key.Prefix, 12)
	}
}

func TestApiKeyService_DuplicateName(t *testing.T) {
	service, ctx := newApiKeyService(t)

	_, err := service.Create(ctx, "acme", "backend")
	require.NoError(t, err)
	_, err = service.Create(ctx, "acme", "backend")
	var duplicate ApiKeyDuplicateError
	assert.ErrorAs(t, err, &duplicate)

	// same name in another tenant is fine
	_, err = service.Create(ctx, "other", "backend")
	assert.NoError(t, err)
}

func TestApiKeyService_Revoke(t *testing.T) {
	service, ctx := newApiKeyService(t)

	created, err := service.Create(ctx, "acme", "backend")
	require.NoError(t, err)

	require.NoError(t, service.Revoke(ctx, "acme", created.ID))
	_, err = service.Authenticate(ctx, created.Key)
	var invalid InvalidApiKeyError
	assert.ErrorAs(t, err, &invalid)

	err = service.Revoke(ctx, "acme", created.ID)
	var notFound ApiKeyNotFoundError
	assert.ErrorAs(t, err, &notFound)

	// revoking across tenants fails
	other, err := service.Create(ctx, "other", "backend")
	require.NoError(t, err)
	err = service.Revoke(ctx, "acme", other.ID)
	assert.ErrorAs(t, err, &notFound)
}
