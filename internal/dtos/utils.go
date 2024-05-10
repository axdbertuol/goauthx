package dtos

import (
	"log"
	"net/http"

	"github.com/axdbertuol/goauthx/internal/constants"
	gut "github.com/axdbertuol/goutils/types"

	"github.com/labstack/echo/v4"
)

func BindAndValidate(dto interface{}, c echo.Context) error {
	if err := c.Bind(dto); err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      err.Error(),
			InternalCode: constants.BIND_FAILED,
		}
	}
	log.Println("asfdas", dto)
	if err := c.Validate(dto); err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      err.Error(),
			InternalCode: constants.FIELD_VALIDATION_ERR,
		}
	}
	return nil
}
