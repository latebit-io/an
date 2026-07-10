package health

import "github.com/labstack/echo/v5"

func HealthRoutes(e *echo.Echo, handler HealthHandler, middleware ...echo.MiddlewareFunc) {
	e.GET("/health", handler.Health, middleware...)
}
