package oidc

import "github.com/labstack/echo/v5"

// ClientRoutes registers the admin surface for OIDC clients. Same middleware
// as accounts and api keys: these calls mint and destroy credentials, so they
// are bootstrap-key only, never a session.
func ClientRoutes(e *echo.Echo, handler ClientHandler, middleware ...echo.MiddlewareFunc) {
	e.POST("/api/oidc/clients", handler.Create, middleware...)
	e.PUT("/api/oidc/clients/delete", handler.Delete, middleware...)
}
