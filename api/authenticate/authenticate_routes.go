package authenticate

import "github.com/labstack/echo/v5"

func LogonCodeRoutes(e *echo.Echo, handler LogonCodeHandler, middleware ...echo.MiddlewareFunc) {
	e.POST("/api/authenticate/code/request", handler.Request, middleware...)
	e.POST("/api/authenticate/code", handler.Logon, middleware...)
}

func SocialRoutes(e *echo.Echo, handler SocialHandler, middleware ...echo.MiddlewareFunc) {
	e.POST("/api/authenticate/social", handler.Logon, middleware...)
}

func AuthenticateRoutes(e *echo.Echo, handler AuthenticateHandler, middleware ...echo.MiddlewareFunc) {
	e.POST("/api/authenticate", handler.Authenticate, middleware...)
	e.POST("/api/authenticate/ack", handler.Acknowledge, middleware...)
	e.POST("/api/authenticate/renew", handler.Renew, middleware...)
	e.PUT("/api/authenticate/revoke", handler.Revoke, middleware...)
	e.POST("/api/authenticate/validate", handler.Validate, middleware...)
}
