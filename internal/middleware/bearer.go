package internal_middleware

import (
	"errors"
	"net/http"
	"strings"

	gut "github.com/axdbertuol/goutils/types"

	"github.com/axdbertuol/goauthx/internal/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

// BearerAuthMiddleware is a middleware function to validate bearer tokens.
func BearerAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Extract the bearer token from the Authorization header
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return &gut.CustomError{
				Code:         http.StatusUnauthorized,
				Message:      "invalid or missing Bearer token",
				InternalCode: "authHeader:NotFound:bearerAuthMiddleware",
			}
		}

		authParts := strings.Split(authHeader, " ")
		if len(authParts) != 2 || strings.ToLower(authParts[0]) != "bearer" {
			return &gut.CustomError{
				Code:         http.StatusUnauthorized,
				Message:      "invalid or missing Bearer token",
				InternalCode: "authHeader:Invalid:bearerAuthMiddleware",
			}
		}

		// Extract the token from the authParts
		token := authParts[1]

		// Perform token validation (you can customize this part according to your token validation logic)
		// Example: validateToken function returns true if the token is valid
		sc := viper.GetString("JWT_SECRET")
		claims, err := utils.ValidateJwt(token, sc, jwt.WithoutClaimsValidation())
		c.Set("accessTokenExpired", false)
		if err != nil {
			if !errors.Is(err, jwt.ErrTokenExpired) {
				return &gut.CustomError{
					Code:         http.StatusUnauthorized,
					Message:      "invalid or missing Bearer token",
					InternalCode: "authHeader:InvalidJwt:bearerAuthMiddleware",
				}
			}
			c.Set("accessTokenExpired", true)
		} else {
			c.Set("accessClaims", claims)
			// Set the userId in the context
			c.Set("userId", claims.UserID)
		}

		c.Set("bearerToken", token)
		// If the token is valid, proceed to the next middleware or handler
		return next(c)
	}
}
