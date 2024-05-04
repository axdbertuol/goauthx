package internal_middleware

import (
	"net/http"
	"regexp"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

// PasswordValidatorMiddleware validates the password format using regex.
func PasswordValidatorMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		password := c.FormValue("password")
		// Regular expression pattern for a strong password
		pattern := `^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$`

		// Compile the regex pattern
		regex := regexp.MustCompile(pattern)
		// Regular expression for password validation

		match := regex.MatchString(password)
		if !match {
			return echo.NewHTTPError(
				http.StatusBadRequest,
				"Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one digit",
			)
		}

		return next(c)
	}
}

// Custom validation function for the "password" field
func ValidatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	// Regular expression pattern for at least one uppercase letter and one digit
	pattern := `^(?=.*[A-Z])(?=.*\d).+$`

	// Compile the regex pattern
	regex := regexp.MustCompile(pattern)

	// Test if the password matches the pattern
	if !regex.MatchString(password) {
		return false
	}

	return true
}
