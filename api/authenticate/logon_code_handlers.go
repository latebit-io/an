package authenticate

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/api/auth"
	"github.com/latebit-io/an/api/problem"
	"github.com/latebit-io/an/internal/authn"
)

type LogonCodeHandler struct {
	codes authn.LogonCodeService
}

type RequestCodeRequest struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
}

type CodeLogonRequest struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
	ClientID string `json:"clientId"`
	Code     string `json:"code"`
}

func NewLogonCodeHandler(service authn.LogonCodeService) LogonCodeHandler {
	return LogonCodeHandler{service}
}

// Request mints a one-time 6-digit logon code and returns it; the caller
// delivers it (an sends no email).
func (lh LogonCodeHandler) Request(c *echo.Context) error {
	request := new(RequestCodeRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	issued, err := lh.codes.Request(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email)
	if err != nil {
		return logonCodeProblem(c, err)
	}

	return c.JSON(http.StatusOK, issued)
}

// Logon exchanges a logon code for a token pair.
func (lh LogonCodeHandler) Logon(c *echo.Context) error {
	request := new(CodeLogonRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	authenticated, err := lh.codes.Authenticate(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email, request.ClientID, request.Code)
	if err != nil {
		return logonCodeProblem(c, err)
	}

	return c.JSON(http.StatusOK, authenticated)
}

func logonCodeProblem(c *echo.Context, err error) error {
	var codeInvalid authn.LogonCodeInvalidError
	if errors.As(err, &codeInvalid) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem(problem.Unauthorized, http.StatusUnauthorized, err))
	}
	var codeExpired authn.LogonCodeExpiredError
	if errors.As(err, &codeExpired) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem(problem.Unauthorized, http.StatusUnauthorized, err))
	}
	return authenticateProblem(c, err)
}
