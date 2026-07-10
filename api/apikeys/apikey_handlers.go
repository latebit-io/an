package apikeys

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/latebit-io/an/api/auth"
	"github.com/latebit-io/an/api/problem"
	"github.com/latebit-io/an/internal/apikeys"
)

type ApiKeyHandler struct {
	apiKeys apikeys.ApiKeyService
}

type CreateApiKeyRequest struct {
	TenantID string `json:"tenantId"`
	Name     string `json:"name"`
}

type ListApiKeysRequest struct {
	TenantID string `json:"tenantId"`
}

type RevokeApiKeyRequest struct {
	TenantID string `json:"tenantId"`
	ID       string `json:"id"`
}

func NewApiKeyHandler(service apikeys.ApiKeyService) ApiKeyHandler {
	return ApiKeyHandler{service}
}

// Create mints a tenant-scoped api key; the secret appears only in this
// response. Bootstrap key only.
func (ah ApiKeyHandler) Create(c *echo.Context) error {
	if !auth.IsRoot(c) {
		return forbidden(c)
	}
	request := new(CreateApiKeyRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	created, err := ah.apiKeys.Create(c.Request().Context(), auth.EffectiveTenant(c, request.TenantID), request.Name)
	if err != nil {
		return apiKeyProblem(c, err)
	}

	return c.JSON(http.StatusCreated, created)
}

// List returns a tenant's keys (prefixes only, never secrets). Bootstrap key
// only.
func (ah ApiKeyHandler) List(c *echo.Context) error {
	if !auth.IsRoot(c) {
		return forbidden(c)
	}
	request := new(ListApiKeysRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	keys, err := ah.apiKeys.List(c.Request().Context(), auth.EffectiveTenant(c, request.TenantID))
	if err != nil {
		return apiKeyProblem(c, err)
	}

	return c.JSON(http.StatusOK, keys)
}

// Revoke deletes an api key. Bootstrap key only.
func (ah ApiKeyHandler) Revoke(c *echo.Context) error {
	if !auth.IsRoot(c) {
		return forbidden(c)
	}
	request := new(RevokeApiKeyRequest)
	if err := c.Bind(request); err != nil {
		httpError := problem.NewBadRequest(err)
		return c.JSON(httpError.Status, httpError)
	}

	err := ah.apiKeys.Revoke(c.Request().Context(), auth.EffectiveTenant(c, request.TenantID), request.ID)
	if err != nil {
		return apiKeyProblem(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

func forbidden(c *echo.Context) error {
	return c.JSON(http.StatusForbidden, problem.NewProblem(problem.Forbidden, http.StatusForbidden,
		errors.New("api key management requires the bootstrap key")))
}

func apiKeyProblem(c *echo.Context, err error) error {
	var notFound apikeys.ApiKeyNotFoundError
	if errors.As(err, &notFound) {
		return c.JSON(http.StatusNotFound, problem.NewProblem("Api key not found", http.StatusNotFound, err))
	}
	var duplicate apikeys.ApiKeyDuplicateError
	if errors.As(err, &duplicate) {
		return c.JSON(http.StatusConflict, problem.NewProblem("Duplicate api key", http.StatusConflict, err))
	}
	var invalid apikeys.InvalidApiKeyRequestError
	if errors.As(err, &invalid) {
		return c.JSON(http.StatusBadRequest, problem.NewProblem("Invalid api key request", http.StatusBadRequest, err))
	}

	httpError := problem.NewServerError(err)
	return c.JSON(httpError.Status, httpError)
}
