package handlers

import (
	"net/http"

	gud "github.com/axdbertuol/goutils/dtos"
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

	e.GET("/user-credentials", ah.GetAllUserIdentities)
	e.GET("/user-credentials/:id", ah.GetUserCredentialsByID)
	e.POST("/register-credentials", ah.CreateUserCredentials)
	e.PATCH("/user-credentials/:id", ah.UpdateUserCredentials)
	e.DELETE("/user-credentials/:id", ah.DeleteUserCredentials)

}

// SignUp handles user registration.
// @Summary Register a new user
// @Description Register a new user with the provided details
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body dtos.CreateUserCredentialsDTO true "User registration details"
// @Success 201 {string} string "User created successfully"
// @Failure 400 {object} gud.ErrorResponse "Invalid request payload"
// @Failure 409 {object} gud.ErrorResponse "Username or email already exists"
// @Failure 500 {object} gud.ErrorResponse "Failed to create user"
// @Router /auth/signup [post]
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

// SignInWithGoogle handles the sign-in with Google functionality.
// This endpoint receives a Google ID token, validates it, and creates or retrieves a user profile accordingly.
// If the user is successfully authenticated, it generates and returns access and refresh tokens.
// @Summary Sign in with Google
// @Tags Auth
// @Description Handles the sign-in with Google functionality.
// @Accept json
// @Produce json
// @Param idToken formData string true "Google ID token"
// @Success 200 {object} dtos.TokenDTOResponse "Successful sign-in"
// @Failure 400 {object} gud.ErrorResponse "Bad request"
// @Failure 401 {object} gud.ErrorResponse "Unauthorized"
// @Failure 404 {object} gud.ErrorResponse "Not found"
// @Failure 500 {object} gud.ErrorResponse "Internal server error"
// @Router /auth/google [post]
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

// Login handles user login.
// @Summary User login
// @Description Authenticate user with provided credentials and issue a JWT token
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body dtos.LoginDTO true "User login details"
// @Success 200 {object} dtos.TokenDTOResponse "JWT token"
// @Failure 400 {object} gud.ErrorResponse "Invalid request payload"
// @Failure 401 {object} gud.ErrorResponse "Invalid username or password"
// @Failure 500 {object} gud.ErrorResponse "Failed to generate token"
// @Router /auth/login [post]
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

// RenewTokens refreshes the JWT token.
// @Summary Refresh JWT token
// @Description Refresh JWT token if it's within 30 minutes of expiration
// @Tags Auth
// @Accept json
// @Produce json
// @Param Authorization header string true "JWT token"
// @Success 200 {object} dtos.TokenDTOResponse "New JWT token"
// @Failure 400 {object} gud.ErrorResponse "Invalid token"
// @Failure 401 {object} gud.ErrorResponse "Token can't be refreshed yet"
// @Failure 500 {object} gud.ErrorResponse "Failed to generate new token"
// @Router /auth/renew-tokens [post]
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

// GetUserCredentialsByID handles the request to retrieve a user profile by ID.
// @Summary Get a user profile by ID
// @Description Retrieve a user profile by its ID
// @ID get-user-profile-by-id
// @Param id path uuid.UUID true "User Profile ID"
// @Produce json
// @Success 200 {object} models.UserCredentials
// @Failure 404 {object} gud.ErrorResponse
// @Failure 500 {object} gud.ErrorResponse
// @Router /user/profile/{id} [get]
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

// UpdateUserCredentials handles the request to update a user profile.
// @Summary Update a user profile
// @Description Update an existing user profile
// @ID update-user-profile
// @Param id path string true "User Profile ID"
// @Accept json
// @Produce json
// @Param user body models.UserCredentials true "User Profile object"
// @Success 200 {object} dtos.UserCredentialsResponse
// @Failure 400 {object} gud.ErrorResponse
// @Failure 404 {object} gud.ErrorResponse
// @Failure 500 {object} gud.ErrorResponse
// @Router /user/profile/{id} [put]
func (h *AuthHandler) UpdateUserCredentials(c echo.Context) error {
	ucreds := new(models.UserCredentials)
	dto := new(dtos.UpdateUserCredentialsDTO)

	id := c.Param("user_id")
	userId, err := uuid.Parse(id)
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

	dto.UserId = userId

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

// GetAllUserCredentialss handles the request to retrieve all user profiles.
// @Summary Get all user profiles
// @Description Retrieve all user profiles
// @Produce json
// @Success 200 {array} models.UserCredentials
// @Failure 500 {object} gud.ErrorResponse
// @Router /user/profile [get]
func (h *AuthHandler) GetAllUserIdentities(c echo.Context) error {

	ucreds, err := h.authService.GetAllUserIdentities(c.Request())
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, ucreds)
}

// DeleteUserCredentials handles the request to delete a user profile.
// @Summary Delete a user profile
// @Description Delete a user profile by its ID
// @ID delete-user-profile
// @Param id path string true "User Profile ID"
// @Success 204
// @Failure 404 {object} gud.ErrorResponse
// @Failure 500 {object} gud.ErrorResponse
// @Router /user/profile/{id} [delete]
func (h *AuthHandler) DeleteUserCredentials(c echo.Context) error {
	userID := c.Param("user_id")

	actualUserId, err := uuid.Parse(userID)
	if err != nil {
		return echo.NewHTTPError(
			http.StatusBadRequest,
			gud.NewErrorResponse("invalid id ", err.Error()),
		)
	}
	if err := h.authService.DeleteUserCredentials(actualUserId); err != nil {
		return err
	}

	return c.NoContent(http.StatusNoContent)
}
