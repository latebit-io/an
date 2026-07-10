package accounts

import "github.com/labstack/echo/v5"

func AccountRoutes(e *echo.Echo, handler AccountHandler, middleware ...echo.MiddlewareFunc) {
	e.POST("/api/accounts", handler.Register, middleware...)
	e.POST("/api/accounts/verify", handler.Verify, middleware...)
	e.POST("/api/accounts/verify/resend", handler.ResendVerification, middleware...)
	e.POST("/api/accounts/forgot", handler.Forgot, middleware...)
	e.POST("/api/accounts/reset", handler.Reset, middleware...)
	e.PUT("/api/accounts/password", handler.UpdatePassword, middleware...)
	e.PUT("/api/accounts/delete", handler.Delete, middleware...)
}
