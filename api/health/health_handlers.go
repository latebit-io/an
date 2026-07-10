package health

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

type HealthHandler struct{}

func NewHealthHandler() HealthHandler {
	return HealthHandler{}
}

func (h HealthHandler) Health(c *echo.Context) error {
	return c.String(http.StatusOK, "OK")
}
