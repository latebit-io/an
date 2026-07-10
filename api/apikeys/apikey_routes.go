package apikeys

import "github.com/labstack/echo/v5"

func ApiKeyRoutes(e *echo.Echo, handler ApiKeyHandler, middleware ...echo.MiddlewareFunc) {
	e.POST("/api/apikeys", handler.Create, middleware...)
	e.POST("/api/apikeys/list", handler.List, middleware...)
	e.PUT("/api/apikeys/delete", handler.Revoke, middleware...)
}
