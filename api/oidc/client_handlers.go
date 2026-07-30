package oidc

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/api/auth"
	"github.com/latebit-io/an/api/problem"
	oidcinternal "github.com/latebit-io/an/internal/oidc"
)

// ClientHandler registers the OIDC clients an application authenticates as.
//
// A hosted box's broker is one of these: its own client rather than a share
// of somebody else's, so a compromise is one tenant's problem and revoking it
// does not lock out the fleet.
type ClientHandler struct {
	clients oidcinternal.ClientRepository
	// reserved is the id of the configured client. The registry resolves it
	// first, so a registration under the same id would be handed a secret
	// that never authenticates and would shadow the deployment's own client
	// for every tenant.
	reserved string
}

func NewClientHandler(clients oidcinternal.ClientRepository, reserved string) ClientHandler {
	return ClientHandler{clients: clients, reserved: reserved}
}

type CreateClientRequest struct {
	TenantID string `json:"tenantId"`
	// ClientID is chosen by the caller so it can name what the client is for.
	ClientID string `json:"clientId"`
	Name     string `json:"name"`
	// RedirectURIs is where this client may be sent back to after a login.
	// Required: a client with none can never complete one.
	RedirectURIs           []string `json:"redirectUris"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
}

type DeleteClientRequest struct {
	TenantID string `json:"tenantId"`
	ClientID string `json:"clientId"`
}

// CreateClientResponse carries the secret, which is the only time it exists
// anywhere but in the caller's hands. Only its hash is stored.
type CreateClientResponse struct {
	TenantID     string   `json:"tenantId"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	RedirectURIs []string `json:"redirectUris"`
}

// Create registers a client and returns its secret once. Bootstrap key only.
func (ch ClientHandler) Create(c *echo.Context) error {
	if !auth.IsRoot(c) {
		return clientForbidden(c)
	}
	request := new(CreateClientRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}
	clientID, err := ch.validateClient(request)
	if err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	created, secret, err := ch.clients.Create(c.Request().Context(), oidcinternal.RegisteredClient{
		TenantID: auth.EffectiveTenant(c, request.TenantID),
		// The validated id, not the raw one: " console " passes a trimmed
		// check and would then be stored padded, resolving as neither.
		ClientID:               clientID,
		RedirectURIs:           request.RedirectURIs,
		PostLogoutRedirectURIs: request.PostLogoutRedirectURIs,
		// Every client registered this way is one of ours. A third party
		// client needs a consent screen that does not exist yet.
		FirstParty: true,
		Name:       request.Name,
	})
	if err != nil {
		return clientProblem(c, err)
	}

	return c.JSON(http.StatusCreated, CreateClientResponse{
		TenantID:     created.TenantID,
		ClientID:     created.ClientID,
		ClientSecret: secret,
		RedirectURIs: created.RedirectURIs,
	})
}

// Delete removes a client. Bootstrap key only.
//
// The credential dies with it: a client left registered for a machine that no
// longer exists is a live way in that nothing is watching.
func (ch ClientHandler) Delete(c *echo.Context) error {
	if !auth.IsRoot(c) {
		return clientForbidden(c)
	}
	request := new(DeleteClientRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	err := ch.clients.Delete(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.ClientID)
	if err != nil {
		return clientProblem(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// validateClient refuses a client that could never complete a login, or one
// that would be shadowed, so the failure lands at registration rather than at
// a tenant's first sign-in. It returns the id to store: validating a trimmed
// value and persisting the raw one is how a client ends up registered under a
// name that resolves as neither.
func (ch ClientHandler) validateClient(request *CreateClientRequest) (string, error) {
	clientID := strings.TrimSpace(request.ClientID)
	if clientID == "" {
		return "", errors.New("clientId is required")
	}
	if ch.reserved != "" && clientID == ch.reserved {
		return "", errors.New("clientId is reserved by the configured client")
	}
	if len(request.RedirectURIs) == 0 {
		return "", errors.New("at least one redirectUri is required")
	}
	for _, uri := range request.RedirectURIs {
		if err := validateRedirectURI("redirectUris", uri); err != nil {
			return "", err
		}
	}
	for _, uri := range request.PostLogoutRedirectURIs {
		if err := validateRedirectURI("postLogoutRedirectUris", uri); err != nil {
			return "", err
		}
	}
	return clientID, nil
}

// validateRedirectURI parses rather than prefix-matches: "https://" passes a
// prefix check and is not a URL anyone can be sent to. Plaintext is refused
// because an authorization code delivered over http is a code on the wire,
// with loopback the one exception a local run needs.
func validateRedirectURI(field, uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%s must be absolute URLs with a host", field)
	}
	// RFC 6749 section 3.1.2: a redirection endpoint carries no fragment.
	// Checked on the raw value because a bare trailing "#" parses to an empty
	// fragment and would otherwise pass.
	if strings.Contains(uri, "#") {
		return fmt.Errorf("%s must not contain a fragment", field)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("%s must be https except on loopback", field)
	}
	return fmt.Errorf("%s must be https", field)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func clientProblem(c *echo.Context, err error) error {
	var duplicate oidcinternal.DuplicateError
	var notFound oidcinternal.ClientNotFoundError
	switch {
	case errors.As(err, &duplicate):
		return c.JSON(http.StatusConflict,
			problem.NewProblem("Duplicate client", http.StatusConflict, err))
	case errors.As(err, &notFound):
		return c.JSON(http.StatusNotFound,
			problem.NewProblem("Client not found", http.StatusNotFound, err))
	}
	httpError := problem.NewServerError(err)
	return c.JSON(httpError.Status, httpError)
}

func clientForbidden(c *echo.Context) error {
	return c.JSON(http.StatusForbidden, problem.NewProblem(problem.Forbidden,
		http.StatusForbidden, errors.New("bootstrap api key required")))
}
