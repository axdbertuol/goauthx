package handlers

import (
	"net/http"
	"strconv"

	gut "github.com/axdbertuol/goutils/types"
	"github.com/google/uuid"

	"github.com/axdbertuol/goauthx/internal/constants"
	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/axdbertuol/goauthx/internal/models"
	"github.com/axdbertuol/goauthx/internal/services"
	"github.com/labstack/echo/v4"
)

type Authenticator interface {
	RegisterAuthRoutes(
		e *echo.Group,
		bearerMw func(echo.HandlerFunc) echo.HandlerFunc,
	)
}

type AuthHandler struct {
	Authenticator
	// Define any dependencies here
	authService services.AuthServicer
}

func NewAuthHandler(
	as services.AuthServicer,
) Authenticator {

	return &AuthHandler{authService: as}
}

func (ah *AuthHandler) RegisterAuthRoutes(
	e *echo.Group,
	bearerMw func(echo.HandlerFunc) echo.HandlerFunc,
) {
	e.POST("/login", ah.Login)
	e.POST("/google/login", ah.SignInWithGoogle)
	e.POST("/renew-tokens", ah.RenewTokens, bearerMw)
	e.POST("/register", ah.CreateUserCredentials)

	e.GET("/credentials", ah.GetAllUserCredentials)
	e.GET("/credentials/:id", ah.GetUserCredentialsByID)
	e.PATCH("/credentials/:id", ah.UpdateUserCredentials)
	e.DELETE("/credentials/:id", ah.DeleteUserCredentials)

}

func (h *AuthHandler) CreateUserCredentials(c echo.Context) error {
	// Parse request body
	// Validate DTO
	signUpDTO := new(dtos.CreateUserCredentialsDTO)
	ucreds := new(models.UserCredentials)
	if err := signUpDTO.BindAndValidate(c); err != nil {
		return err
	}

	if err := h.authService.CreateUserCredentials(ucreds, signUpDTO); err != nil {
		return err
	}

	return c.JSON(http.StatusCreated, ucreds.ToDto())
}

func (h *AuthHandler) SignInWithGoogle(c echo.Context) error {
	var (
		signUpDTO = new(dtos.LoginGoogleDTO)
		tokenResp = new(dtos.TokenDTOResponse)
	)
	if err := signUpDTO.BindAndValidate(c); err != nil {
		return err
	}

	if err := h.authService.SignInWithGoogle(tokenResp, signUpDTO); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, tokenResp)
}

func (h *AuthHandler) Login(c echo.Context) error {
	// Parse request body
	loginDTO := new(dtos.LoginDTO)
	tokenResp := new(dtos.TokenDTOResponse)
	if err := loginDTO.BindAndValidate(c); err != nil {
		return err
	}

	if err := h.authService.Login(tokenResp, loginDTO); err != nil {
		return err
	}
	// Return token in response
	return c.JSON(http.StatusOK, tokenResp)
}

func (h *AuthHandler) RenewTokens(c echo.Context) error {

	dto := &dtos.RenewTokensDTO{}
	tokenResp := &dtos.TokenDTOResponse{}
	accessToken, ok := c.Get("bearerToken").(string)

	if accessToken == "" || !ok {
		customErr := &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      "bearer token is required",
			InternalCode: constants.MISSING_BEARER_TOKEN,
		}
		return customErr
	}
	if err := c.Bind(dto); err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      err.Error(),
			InternalCode: constants.BIND_FAILED,
		}
	}

	if err := c.Validate(dto); err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      err.Error(),
			InternalCode: constants.FIELD_VALIDATION_ERR,
		}
	}

	accessClaims, ok := c.Get("accessClaims").(*dtos.JwtCustomClaims)
	if !ok || accessClaims == nil {
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      "accessClaims is invalid or missing",
			InternalCode: "accessClaims:InvalidOrMissing:RenewTokens",
		}
	}

	if err := h.authService.RenewTokens(tokenResp, dto, accessClaims); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, tokenResp)
}

func (h *AuthHandler) GetUserCredentialsByID(c echo.Context) error {
	dto := new(dtos.GetUserCredentialsDTO)
	ucreds := new(models.UserCredentials)

	userProfID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      "invalid user id",
			InternalCode: "userId:Invalid:GetUserCredentialsByID",
		}
	}
	if err := h.authService.GetUserCredentialsByID(ucreds, userProfID); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, dto)
}

func (h *AuthHandler) UpdateUserCredentials(c echo.Context) error {
	ucreds := new(models.UserCredentials)
	dto := new(dtos.UpdateUserCredentialsDTO)

	id := c.Param("user_id")
	userId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      err.Error(),
			InternalCode: "userId:Invalid:UpdateUserCredentials",
		}
	}

	// Bind the request body to the user struct
	if err := c.Bind(&dto); err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      err.Error(),
			InternalCode: "userId:BindFail:UpdateUserCredentials",
		}
	}

	dto.UserId = uint(userId)

	// Validate the user struct
	if err := c.Validate(&dto); err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      err.Error(),
			InternalCode: "userId:Invalid:UpdateUserCredentials",
		}
	}

	if err := h.authService.UpdateUserCredentials(ucreds, dto); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, dto)
}

func (h *AuthHandler) GetAllUserCredentials(c echo.Context) error {

	ucreds, err := h.authService.GetAllUserCredentials(c.Request())
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, ucreds)
}

func (h *AuthHandler) DeleteUserCredentials(c echo.Context) error {
	userIDstr := c.Param("user_id")
	userId, err := strconv.ParseUint(userIDstr, 10, 64)
	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      err.Error(),
			InternalCode: "userId:Invalid:UpdateUserCredentials",
		}
	}
	if err := h.authService.DeleteUserCredentials(uint(userId)); err != nil {
		return err
	}

	return c.NoContent(http.StatusNoContent)
}
