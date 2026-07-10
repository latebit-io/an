package jwks

import "github.com/labstack/echo/v5"

func JwksRoutes(e *echo.Echo, handler JwksHandler, middleware ...echo.MiddlewareFunc) {
	e.GET("/.well-known/jwks.json", handler.Keys, middleware...)
}
