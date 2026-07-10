package jwks

import (
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/api/problem"
	"github.com/latebit-io/an/internal/tokens"
)

type JwksHandler struct {
	signingKeys tokens.SigningKeyService
}

func NewJwksHandler(service tokens.SigningKeyService) JwksHandler {
	return JwksHandler{service}
}

// Keys serves the public signing keys as an RFC 7517 JWKS so consumers can
// verify access tokens locally without calling the validate endpoint.
func (jh JwksHandler) Keys(c *echo.Context) error {
	keySet, err := jh.signingKeys.JWKS(c.Request().Context())
	if err != nil {
		httpError := problem.NewServerError(err)
		return c.JSON(httpError.Status, httpError)
	}
	return c.JSON(http.StatusOK, keySet)
}
