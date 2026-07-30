package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The configured client is resolved first, so a registration under its id
// would hand back a secret that never authenticates and shadow the
// deployment's own client for every tenant.
func TestReservedClientIDIsRefused(t *testing.T) {
	handler := NewClientHandler(nil, "console")

	err := handler.validateClient(&CreateClientRequest{
		ClientID:     "console",
		RedirectURIs: []string{"https://console.demarkus.io/auth/callback"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

// Prefix matching accepted things that are not addresses. Parsing is what
// separates a URL from a string that starts like one.
func TestRedirectURIsAreParsedNotPrefixMatched(t *testing.T) {
	handler := NewClientHandler(nil, "console")

	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{"https with host", "https://broker.acme.demarkus.io/auth/callback", true},
		{"scheme only", "https://", false},
		{"no scheme", "broker.acme.demarkus.io/auth/callback", false},
		{"plaintext", "http://broker.acme.demarkus.io/auth/callback", false},
		{"loopback plaintext", "http://localhost:8080/auth/callback", true},
		{"loopback address", "http://127.0.0.1:8080/auth/callback", true},
		{"other scheme", "ftp://broker.acme.demarkus.io/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handler.validateClient(&CreateClientRequest{
				ClientID: "broker-a", RedirectURIs: []string{tc.uri},
			})
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// Logout targets are where a browser gets sent too, so they are held to the
// same rule rather than skipped.
func TestPostLogoutRedirectURIsAreValidated(t *testing.T) {
	handler := NewClientHandler(nil, "console")

	err := handler.validateClient(&CreateClientRequest{
		ClientID:               "broker-b",
		RedirectURIs:           []string{"https://broker.acme.demarkus.io/auth/callback"},
		PostLogoutRedirectURIs: []string{"http://phisher.example.com/"},
	})
	assert.Error(t, err)
}

// A client with nowhere to be sent back to can never complete a login.
func TestRedirectURIIsRequired(t *testing.T) {
	handler := NewClientHandler(nil, "console")

	assert.Error(t, handler.validateClient(&CreateClientRequest{ClientID: "broker-c"}))
	assert.Error(t, handler.validateClient(&CreateClientRequest{
		ClientID:     "   ",
		RedirectURIs: []string{"https://broker.acme.demarkus.io/auth/callback"},
	}))
}
