package accounts

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/api/auth"
	"github.com/latebit-io/an/api/problem"
	"github.com/latebit-io/an/internal/accounts"
)

type AccountHandler struct {
	accounts accounts.AccountService
}

type RegisterAccountRequest struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type VerifyAccountRequest struct {
	TenantID          string `json:"tenantId"`
	Email             string `json:"email"`
	VerificationToken string `json:"verificationToken"`
}

type ResendVerificationRequest struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
}

type ResendVerificationResponse struct {
	VerificationToken string `json:"verificationToken"`
}

type ForgotPasswordRequest struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
}

type ResetPasswordRequest struct {
	TenantID    string `json:"tenantId"`
	Email       string `json:"email"`
	ResetToken  string `json:"resetToken"`
	NewPassword string `json:"newPassword"`
}

type UpdatePasswordRequest struct {
	TenantID        string `json:"tenantId"`
	Email           string `json:"email"`
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type DeleteAccountRequest struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
}

func NewAccountHandler(service accounts.AccountService) AccountHandler {
	return AccountHandler{service}
}

// Register creates an account and returns the one-time verification token;
// the caller delivers it (an sends no email).
func (ah AccountHandler) Register(c *echo.Context) error {
	request := new(RegisterAccountRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	registered, err := ah.accounts.Register(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email, request.Password)
	if err != nil {
		return accountProblem(c, err)
	}

	return c.JSON(http.StatusCreated, registered)
}

func (ah AccountHandler) Verify(c *echo.Context) error {
	request := new(VerifyAccountRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	err := ah.accounts.Verify(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email, request.VerificationToken)
	if err != nil {
		return accountProblem(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

// ResendVerification regenerates the verification token and returns it.
func (ah AccountHandler) ResendVerification(c *echo.Context) error {
	request := new(ResendVerificationRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	token, err := ah.accounts.ResendVerification(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email)
	if err != nil {
		return accountProblem(c, err)
	}

	return c.JSON(http.StatusOK, ResendVerificationResponse{VerificationToken: token})
}

// Forgot mints a one-time password reset token and returns it; the caller
// delivers it.
func (ah AccountHandler) Forgot(c *echo.Context) error {
	request := new(ForgotPasswordRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	reset, err := ah.accounts.Forgot(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email)
	if err != nil {
		return accountProblem(c, err)
	}

	return c.JSON(http.StatusOK, reset)
}

// Reset sets a new password from a reset token, revokes every session and
// clears any lockout.
func (ah AccountHandler) Reset(c *echo.Context) error {
	request := new(ResetPasswordRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	err := ah.accounts.Reset(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email, request.ResetToken,
		request.NewPassword)
	if err != nil {
		return accountProblem(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

func (ah AccountHandler) UpdatePassword(c *echo.Context) error {
	request := new(UpdatePasswordRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	err := ah.accounts.UpdatePassword(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email, request.CurrentPassword,
		request.NewPassword)
	if err != nil {
		return accountProblem(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

// Delete soft deletes an account and revokes every session.
func (ah AccountHandler) Delete(c *echo.Context) error {
	request := new(DeleteAccountRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	err := ah.accounts.Delete(c.Request().Context(),
		auth.EffectiveTenant(c, request.TenantID), request.Email)
	if err != nil {
		return accountProblem(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

func accountProblem(c *echo.Context, err error) error {
	var notFound accounts.AccountNotFoundError
	if errors.As(err, &notFound) {
		return c.JSON(http.StatusNotFound, problem.NewProblem("Account not found", http.StatusNotFound, err))
	}
	var duplicate accounts.AccountDuplicateError
	if errors.As(err, &duplicate) {
		return c.JSON(http.StatusConflict, problem.NewProblem("Duplicate account", http.StatusConflict, err))
	}
	var invalid accounts.InvalidAccountError
	if errors.As(err, &invalid) {
		return c.JSON(http.StatusBadRequest, problem.NewProblem("Invalid account request", http.StatusBadRequest, err))
	}
	var verification accounts.VerificationError
	if errors.As(err, &verification) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem("Verification failed", http.StatusUnauthorized, err))
	}
	var resetInvalid accounts.ResetTokenInvalidError
	if errors.As(err, &resetInvalid) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem("Invalid reset token", http.StatusUnauthorized, err))
	}
	var resetExpired accounts.ResetTokenExpiredError
	if errors.As(err, &resetExpired) {
		return c.JSON(http.StatusUnauthorized, problem.NewProblem("Reset token expired", http.StatusUnauthorized, err))
	}

	httpError := problem.NewServerError(err)
	return c.JSON(httpError.Status, httpError)
}
