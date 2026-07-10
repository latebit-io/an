package authenticate

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/api/auth"
	"github.com/latebit-io/an/api/problem"
	"github.com/latebit-io/an/internal/social"
)

type SocialHandler struct {
	social social.SocialService
}

type SocialLogonRequest struct {
	TenantID string `json:"tenantId"`
	Provider string `json:"provider"`
	IDToken  string `json:"idToken"`
	ClientID string `json:"clientId"`
}

func NewSocialHandler(service social.SocialService) SocialHandler {
	return SocialHandler{service}
}

// Logon exchanges a provider ID token (e.g. Google) for a token pair,
// creating the account born verified on first sight.
func (sh SocialHandler) Logon(c *echo.Context) error {
	request := new(SocialLogonRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	authenticated, err := sh.social.Authenticate(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Provider, request.IDToken,
		request.ClientID)
	if err != nil {
		return socialProblem(c, err)
	}

	return c.JSON(http.StatusOK, authenticated)
}

func socialProblem(c *echo.Context, err error) error {
	var notConfigured social.ProviderNotConfiguredError
	if errors.As(err, &notConfigured) {
		return c.JSON(http.StatusBadRequest, problem.NewProblem("Provider not configured", http.StatusBadRequest, err))
	}
	var tokenInvalid social.SocialTokenInvalidError
	if errors.As(err, &tokenInvalid) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem(problem.Unauthorized, http.StatusUnauthorized, err))
	}
	var emailNotVerified social.EmailNotVerifiedError
	if errors.As(err, &emailNotVerified) {
		return c.JSON(http.StatusForbidden, problem.NewProblem(problem.Forbidden, http.StatusForbidden, err))
	}
	var alreadyLinked social.SocialAlreadyLinkedError
	if errors.As(err, &alreadyLinked) {
		return c.JSON(http.StatusConflict, problem.NewProblem("Social identity conflict", http.StatusConflict, err))
	}
	return authenticateProblem(c, err)
}
