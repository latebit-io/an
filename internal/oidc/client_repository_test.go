package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/latebit-io/an/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newClients(t *testing.T) ClientRepository {
	t.Helper()
	return NewPostgresClientRepository(utils.NewTestPool(t))
}

func register(t *testing.T, repo ClientRepository, tenantID, clientID string) (*RegisteredClient, string) {
	t.Helper()
	client, secret, err := repo.Create(context.Background(), RegisteredClient{
		TenantID:               tenantID,
		ClientID:               clientID,
		RedirectURIs:           []string{"https://broker." + clientID + ".demarkus.io/auth/callback"},
		PostLogoutRedirectURIs: []string{"https://broker." + clientID + ".demarkus.io/"},
		FirstParty:             true,
		Name:                   clientID,
	})
	require.NoError(t, err)
	return client, secret
}

// The secret exists once, in the response. Anything else is a credential
// sitting in a database that nobody needs it to be in.
func TestClientSecretIsReturnedOnceAndHashedAtRest(t *testing.T) {
	repo := newClients(t)
	created, secret := register(t, repo, "default", "broker-a")

	require.NotEmpty(t, secret)
	assert.Equal(t, utils.Sha256Hex(secret), created.SecretHash)

	read, err := repo.Read(context.Background(), "default", "broker-a")
	require.NoError(t, err)
	assert.Equal(t, utils.Sha256Hex(secret), read.SecretHash)
	assert.NotContains(t, read.SecretHash, secret)
}

// A client id resolved without its tenant would let a client registered for
// one tenant authenticate against another.
func TestClientReadsAreTenantScoped(t *testing.T) {
	repo := newClients(t)
	register(t, repo, "acme", "broker-shared")

	_, err := repo.Read(context.Background(), "other", "broker-shared")
	assert.ErrorAs(t, err, &ClientNotFoundError{})
}

// Registering the same id twice must not quietly replace the first client's
// secret: the box already holding it would stop authenticating.
func TestDuplicateClientIsRefused(t *testing.T) {
	repo := newClients(t)
	register(t, repo, "default", "broker-b")

	_, _, err := repo.Create(context.Background(), RegisteredClient{
		TenantID:     "default",
		ClientID:     "broker-b",
		RedirectURIs: []string{"https://elsewhere.example.com/auth/callback"},
		FirstParty:   true,
	})
	assert.ErrorAs(t, err, &DuplicateError{})
}

// Teardown has to actually revoke: a client left behind for a destroyed box
// is a live credential nothing is watching.
func TestDeletedClientStopsResolving(t *testing.T) {
	repo := newClients(t)
	register(t, repo, "default", "broker-c")

	require.NoError(t, repo.Delete(context.Background(), "default", "broker-c"))
	_, err := repo.Read(context.Background(), "default", "broker-c")
	assert.ErrorAs(t, err, &ClientNotFoundError{})

	// Deleting twice is what a retried teardown does.
	assert.ErrorAs(t, repo.Delete(context.Background(), "default", "broker-c"), &ClientNotFoundError{})
}

// The configured client keeps working, which is the whole reason the registry
// is composed rather than a replacement.
func TestConfiguredClientStillResolves(t *testing.T) {
	repo := newClients(t)
	configured := NewStaticClientRegistry(&StaticClient{
		ID:                     "console",
		SecretHash:             utils.Sha256Hex("console-secret"),
		RedirectURIs:           []string{"https://console.demarkus.io/auth/callback"},
		PostLogoutRedirectURIs: []string{"https://console.demarkus.io/login"},
		FirstParty:             true,
		IDTokenLifetime:        time.Hour,
	})
	registry := NewRegistryClientRegistry(configured, repo)
	ctx := context.Background()

	client, err := registry.Client(ctx, "default", "console")
	require.NoError(t, err)
	assert.Equal(t, "console", client.ID)
	require.NoError(t, registry.Authenticate(ctx, "default", "console", "console-secret"))
}

// A registered client authenticates the same way, and its id token lifetime
// comes from the configured one rather than being a second setting.
func TestRegisteredClientAuthenticates(t *testing.T) {
	repo := newClients(t)
	_, secret := register(t, repo, "default", "broker-d")

	configured := NewStaticClientRegistry(&StaticClient{
		ID: "console", SecretHash: utils.Sha256Hex("console-secret"), FirstParty: true,
		IDTokenLifetime: time.Hour,
	})
	registry := NewRegistryClientRegistry(configured, repo)
	ctx := context.Background()

	client, err := registry.Client(ctx, "default", "broker-d")
	require.NoError(t, err)
	assert.Equal(t, time.Hour, client.IDTokenLifetime)
	require.NoError(t, registry.Authenticate(ctx, "default", "broker-d", secret))

	err = registry.Authenticate(ctx, "default", "broker-d", "not-the-secret")
	assert.ErrorAs(t, err, &ClientAuthenticationError{})
}

// Logout may only send a browser where the client said, whichever registry
// resolved it.
func TestPostLogoutRedirectIsValidatedForRegisteredClients(t *testing.T) {
	repo := newClients(t)
	register(t, repo, "default", "broker-e")

	configured := NewStaticClientRegistry(&StaticClient{
		ID: "console", SecretHash: utils.Sha256Hex("x"), FirstParty: true,
		PostLogoutRedirectURIs: []string{"https://console.demarkus.io/login"},
	})
	registry := NewRegistryClientRegistry(configured, repo)
	ctx := context.Background()

	require.NoError(t, registry.PostLogoutRedirect(ctx, "default", "broker-e",
		"https://broker.broker-e.demarkus.io/"))
	assert.ErrorAs(t, registry.PostLogoutRedirect(ctx, "default", "broker-e",
		"https://phisher.example.com/"), &RedirectURINotAllowedError{})
}
