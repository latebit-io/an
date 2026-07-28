package oidc

import (
	"net/http"

	"github.com/labstack/echo/v5"
	internaloidc "github.com/latebit-io/an/internal/oidc"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// DiscoveryPath is where a relying party looks first.
const DiscoveryPath = "/.well-known/openid-configuration"

// The library advertises capabilities this issuer does not have. Its
// response type list is hardcoded (with a TODO to that effect) and it
// reports jwt-bearer support unconditionally, so a client reading discovery
// is told it can use the implicit flow, the jwt-bearer grant, or the device
// flow. Every one of those is refused at request time, which turns an
// unsupported feature into a confusing runtime rejection instead of an
// honest "not supported" at configuration time.
//
// There is no configuration seam for this: op.ResponseTypes ignores config
// entirely and Provider.GrantTypeJWTAuthorizationSupported returns a
// constant. So the document is built with the library's own builder and the
// untrue fields are overwritten before it is served. Everything else,
// endpoints and scopes included, still comes from the library, so this
// cannot drift from what is mounted.
var (
	// supportedResponseTypes is what /authorize actually accepts. Implicit
	// response types are not offered: no client may request them.
	supportedResponseTypes = []string{string(oidc.ResponseTypeCode)}

	// supportedGrantTypes is what /token actually accepts, taken from the
	// same statement the client enforces.
	supportedGrantTypes = internaloidc.SupportedGrantTypes
)

type DiscoveryHandler struct {
	provider      *op.Provider
	publicBaseURL string
}

func NewDiscoveryHandler(provider *op.Provider, publicBaseURL string) DiscoveryHandler {
	return DiscoveryHandler{provider: provider, publicBaseURL: publicBaseURL}
}

// Discovery serves the library's document with the capabilities this issuer
// does not support corrected. Assigning typed fields rather than editing
// JSON keys means a library upgrade that renames one fails the build
// instead of silently reinstating a false claim.
func (h DiscoveryHandler) Discovery(c *echo.Context) error {
	tenantID := c.Param("tenantId")
	if tenantID == "" {
		return c.NoContent(http.StatusNotFound)
	}
	ctx := op.ContextWithIssuer(c.Request().Context(), Issuer(h.publicBaseURL, tenantID))

	document := op.CreateDiscoveryConfig(ctx, h.provider, h.provider.Storage())
	document.ResponseTypesSupported = supportedResponseTypes
	document.GrantTypesSupported = supportedGrantTypes
	// The device flow has no backing storage here, so the endpoint the
	// library publishes answers nothing useful.
	document.DeviceAuthorizationEndpoint = ""

	return c.JSON(http.StatusOK, document)
}
