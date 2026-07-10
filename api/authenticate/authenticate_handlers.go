package authenticate

import (
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/api/auth"
	"github.com/latebit-io/an/api/problem"
	"github.com/latebit-io/an/internal/accounts"
	"github.com/latebit-io/an/internal/authn"
	"github.com/latebit-io/an/internal/tokens"
)

type AuthenticateHandler struct {
	authentication authn.AuthenticationService
}

type AuthenticateRequest struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
	ClientID string `json:"clientId"`
	Password string `json:"password"`
}

type AcknowledgeRequest struct {
	TenantID     string `json:"tenantId"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type RenewRequest struct {
	TenantID     string `json:"tenantId"`
	RefreshToken string `json:"refreshToken"`
}

type RevokeRequest struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
	ClientID string `json:"clientId"`
}

type ValidateRequest struct {
	TenantID    string `json:"tenantId"`
	AccessToken string `json:"accessToken"`
}

// ValidateResponse flattens the access token claims.
type ValidateResponse struct {
	TenantID  string    `json:"tenantId"`
	ClientID  string    `json:"clientId"`
	Subject   string    `json:"subject"`
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	Audience  []string  `json:"audience"`
	ExpiresAt time.Time `json:"expiresAt"`
	IssuedAt  time.Time `json:"issuedAt"`
	NotBefore time.Time `json:"notBefore"`
}

func NewAuthenticateHandler(service authn.AuthenticationService) AuthenticateHandler {
	return AuthenticateHandler{service}
}

// Authenticate is the password logon; it returns a token pair the client
// must acknowledge before validate and renew accept it.
func (ah AuthenticateHandler) Authenticate(c *echo.Context) error {
	request := new(AuthenticateRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	authenticated, err := ah.authentication.Authenticate(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email, request.ClientID,
		request.Password)
	if err != nil {
		return authenticateProblem(c, err)
	}

	return c.JSON(http.StatusOK, authenticated)
}

func (ah AuthenticateHandler) Acknowledge(c *echo.Context) error {
	request := new(AcknowledgeRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	err := ah.authentication.Acknowledge(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), authn.Authenticated{
			AccessToken:  request.AccessToken,
			RefreshToken: request.RefreshToken,
		})
	if err != nil {
		return authenticateProblem(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

// Renew rotates the token pair from an acknowledged refresh token.
func (ah AuthenticateHandler) Renew(c *echo.Context) error {
	request := new(RenewRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	authenticated, err := ah.authentication.Renew(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.RefreshToken)
	if err != nil {
		return authenticateProblem(c, err)
	}

	return c.JSON(http.StatusOK, authenticated)
}

// Revoke deletes one client's session, or all of them when clientId is
// empty.
func (ah AuthenticateHandler) Revoke(c *echo.Context) error {
	request := new(RevokeRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	err := ah.authentication.Revoke(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email, request.ClientID)
	if err != nil {
		return authenticateProblem(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

// Validate checks signature, expiry, tenant and acknowledged session; the
// JWKS endpoint covers signature-only local verification.
func (ah AuthenticateHandler) Validate(c *echo.Context) error {
	request := new(ValidateRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	claims, err := ah.authentication.Validate(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.AccessToken)
	if err != nil {
		return authenticateProblem(c, err)
	}

	return c.JSON(http.StatusOK, ValidateResponse{
		TenantID:  claims.TenantID,
		ClientID:  claims.ClientID,
		Subject:   claims.Subject,
		ID:        claims.ID,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		ExpiresAt: claims.ExpiresAt.Time,
		IssuedAt:  claims.IssuedAt.Time,
		NotBefore: claims.NotBefore.Time,
	})
}

func authenticateProblem(c *echo.Context, err error) error {
	var locked authn.AccountLockedError
	if errors.As(err, &locked) {
		return c.JSON(http.StatusLocked, problem.NewProblem("Account locked", http.StatusLocked, err))
	}
	var authentication authn.AuthenticationError
	if errors.As(err, &authentication) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem(problem.Unauthorized, http.StatusUnauthorized, err))
	}
	var tokenInvalid tokens.TokenInvalidError
	if errors.As(err, &tokenInvalid) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem(problem.Unauthorized, http.StatusUnauthorized, err))
	}
	var notAcknowledged authn.TokenNotAcknowledgedError
	if errors.As(err, &notAcknowledged) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem(problem.Unauthorized, http.StatusUnauthorized, err))
	}
	var tenantMismatch authn.TokenTenantMismatchError
	if errors.As(err, &tenantMismatch) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem(problem.Unauthorized, http.StatusUnauthorized, err))
	}
	var notVerified accounts.AccountNotVerifiedError
	if errors.As(err, &notVerified) {
		return c.JSON(http.StatusForbidden, problem.NewProblem(problem.Forbidden, http.StatusForbidden, err))
	}
	var disabled accounts.AccountDisabledError
	if errors.As(err, &disabled) {
		return c.JSON(http.StatusForbidden, problem.NewProblem(problem.Forbidden, http.StatusForbidden, err))
	}
	var notFound accounts.AccountNotFoundError
	if errors.As(err, &notFound) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem(problem.Unauthorized, http.StatusUnauthorized, err))
	}
	var sessionNotFound authn.SessionNotFoundError
	if errors.As(err, &sessionNotFound) {
		return c.JSON(http.StatusNotFound, problem.NewProblem("Session not found", http.StatusNotFound, err))
	}

	httpError := problem.NewServerError(err)
	return c.JSON(httpError.Status, httpError)
}
