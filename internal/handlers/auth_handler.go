package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	gud "github.com/axdbertuol/goutils/dtos"
	goutils "github.com/axdbertuol/goutils/functions"
	gut "github.com/axdbertuol/goutils/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/api/idtoken"

	"github.com/axdbertuol/auth_service/internal/constants"
	"github.com/axdbertuol/auth_service/internal/dtos"
	"github.com/axdbertuol/auth_service/internal/models"
	"github.com/axdbertuol/auth_service/internal/repository"
	"github.com/axdbertuol/auth_service/internal/services"
	"github.com/axdbertuol/auth_service/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Authenticator interface {
	Handler
	RegisterAuthRoutes(
		e *echo.Group,
		bearerMw func(echo.HandlerFunc) echo.HandlerFunc,
	)
}
type AuthConfig struct {
	jwtSecret string
}
type AuthHandler struct {
	Authenticator
	// Define any dependencies here
	config              *AuthConfig
	UserCredentialsRepo repository.StorableUserCredentialsRepository
}

func NewAuthHandler(
	ur repository.StorableUserCredentialsRepository,
	config *viper.Viper,
) Authenticator {
	secret := config.GetString("JWT_SECRET")

	return &AuthHandler{UserCredentialsRepo: ur, config: &AuthConfig{jwtSecret: secret}}
}

func (ah *AuthHandler) RegisterAuthRoutes(
	e *echo.Group,
	bearerMw func(echo.HandlerFunc) echo.HandlerFunc,
) {
	e.POST("/login", ah.Login)
	e.POST("/renew-tokens", ah.RenewTokens, bearerMw)

	e.GET("/user-credentials", ah.GetAllUserIdentities)
	e.GET("/user-credentials/:id", ah.GetUserCredentialsByID)
	e.POST("/user-credentials", ah.CreateUserCredentials)
	e.PATCH("/user-credentials/:id", ah.UpdateUserCredentials)
	e.DELETE("/user-credentials/:id", ah.DeleteUserCredentials)

}

const (
	accessExpiresIn  = 1 * time.Minute
	refreshExpiresIn = 24 * time.Hour
)

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

	if err := signUpDTO.BindAndValidate(c); err != nil {
		return err
	}

	cred := &models.UserCredentials{
		Username: signUpDTO.Username,
		Email:    signUpDTO.Email,
		Role:     signUpDTO.Role,
		Status:   signUpDTO.Status,
	}

	if signUpDTO.PasswordHash != nil {
		cred.PasswordHash = &signUpDTO.PasswordHash
	}
	if signUpDTO.SocialId != "" {
		cred.SocialId = &signUpDTO.SocialId
	}

	// Create user in the database
	if err := h.UserCredentialsRepo.Create(cred); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return &gut.CustomError{
				Code:         http.StatusConflict,
				Message:      err.Error(),
				InternalCode: ":AlreadyExists:UserCredentials",
			}
		}
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      err.Error(),
			InternalCode: ":CreationFailure:UserCredentials",
		}
	}

	return c.JSON(http.StatusCreated, cred.ToDto())
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
		uIdentity = new(models.UserCredentials)
	)
	if err := signUpDTO.BindAndValidate(c); err != nil {
		return err
	}

	payload, err := idtoken.Validate(
		context.Background(),
		signUpDTO.IdToken,
		"",
	)

	if err != nil {
		errMsg := err.Error() // Get the error message

		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      "Invalid id token: " + errMsg, // Append error message
			InternalCode: "invalidIdToken:google",
		}
	}
	if err := h.UserCredentialsRepo.
		GetFirst(uIdentity, "social_id = ?", &payload.Subject); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &gut.CustomError{
				Code:         http.StatusNotFound,
				Message:      err.Error(),
				InternalCode: "idToken:NotFound:google",
			}
		}
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      "Unable to process idToken", // Append error message
			InternalCode: "idToken:UnknownError:google",
		}
	}

	regClaims := &jwt.RegisteredClaims{
		Issuer:   payload.Issuer,
		Subject:  payload.Subject,
		Audience: []string{payload.Audience},
	}
	jwtGenDto := &dtos.JwtGenDTO{
		UserId:   uIdentity.UserId.String(),
		Username: uIdentity.Username,
		Email:    uIdentity.Email,
		Role:     uIdentity.Role,
	}
	args := &services.TokensGen{
		AccessToken: &services.TokenArgs{
			User:      jwtGenDto,
			ExpiresIn: accessExpiresIn,
			RegClaims: regClaims,
		},
		RefreshToken: &services.TokenArgs{
			User:      jwtGenDto,
			ExpiresIn: refreshExpiresIn,
			RegClaims: regClaims,
		},
		Secret: h.config.jwtSecret,
	}
	// secret := h.config.GetString("JWT_SECRET")
	access_token, refresh_token, err := args.GenerateTokens()
	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      err.Error(),
			InternalCode: "token:GenFailure:google",
		}
	}

	return c.JSON(
		http.StatusOK,
		dtos.TokenDTOResponse{
			Token:        access_token,
			RefreshToken: refresh_token,
			TokenExpires: time.Now().Add(accessExpiresIn),
			User:         *uIdentity.ToDto(),
		},
	)
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
	ucreds := new(models.UserCredentials)
	secret := h.config.jwtSecret

	if err := loginDTO.BindAndValidate(c); err != nil {
		return err
	}

	if loginDTO.Email != nil {
		// Retrieve user by username
		err := h.UserCredentialsRepo.GetUserByEmail(ucreds, *loginDTO.Email)
		if err != nil {
			return &gut.CustomError{
				Code:         http.StatusUnauthorized,
				Message:      err.Error(),
				InternalCode: "email:InvalidCredentials:login",
			}
		}
	} else if loginDTO.Username != nil {
		err := h.UserCredentialsRepo.GetUserByUsername(ucreds, *loginDTO.Username)
		if err != nil {
			return &gut.CustomError{
				Code:         http.StatusUnauthorized,
				Message:      err.Error(),
				InternalCode: "username:InvalidCredentials:login",
			}
		}
	} else {
		return &gut.CustomError{
			Code:         http.StatusUnauthorized,
			Message:      "invalid login:",
			InternalCode: ":InvalidCredentials:login",
		}
	}

	if ucreds.PasswordHash == nil {
		return &gut.CustomError{
			Code:         http.StatusUnauthorized,
			Message:      "invalid login method, should try provider",
			InternalCode: "password:InvalidCredentials:login",
		}
	}

	if err := bcrypt.CompareHashAndPassword(*ucreds.PasswordHash, []byte(loginDTO.Password)); err != nil {
		return &gut.CustomError{
			Code:         http.StatusUnauthorized,
			Message:      err.Error(),
			InternalCode: "password:InvalidCredentials:login",
		}
	}

	jwtGenDto := &dtos.JwtGenDTO{
		UserId:   ucreds.UserId.String(),
		Username: ucreds.Username,
		Email:    ucreds.Email,
		Role:     ucreds.Role,
	}

	tokenArgs := &services.TokensGen{
		AccessToken: &services.TokenArgs{
			User:      jwtGenDto,
			ExpiresIn: accessExpiresIn,
		},
		RefreshToken: &services.TokenArgs{
			User:      jwtGenDto,
			ExpiresIn: refreshExpiresIn,
		},
		Secret: secret,
	}

	accessToken, refreshToken, err := tokenArgs.GenerateTokens()

	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      "failed to generate tokens: " + err.Error(),
			InternalCode: "token:GenFailure:login",
		}
	}

	// Return token in response
	return c.JSON(
		http.StatusOK,
		dtos.TokenDTOResponse{
			Token:        accessToken,
			RefreshToken: refreshToken,
			TokenExpires: time.Now().Add(accessExpiresIn),
			User:         *ucreds.ToDto(),
		},
	)
}

// CheckTokenExpired checks if the provided token has expired.
// @Summary Check Token Expiration
// @Description Check if the provided JWT token has expired
// @Tags Auth
// @Accept json
// @Produce json
// @Param Authorization header string true "JWT token"
// @Success 200 {string} string "Token is valid"
// @Failure 400 {object} gud.ErrorResponse "Invalid token"
// @Failure 401 {object} gud.ErrorResponse "Token is invalid"
// @Router /auth/check-token [get]
func (h *AuthHandler) CheckTokenExpired(c echo.Context) error {
	reqToken := c.Request().Header.Get("Authorization")
	if reqToken == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, gud.NewErrorResponse("missing token"))
	}
	sc := h.config.jwtSecret
	claims, err := utils.ValidateJwt(reqToken, sc)
	if err != nil {
		return echo.NewHTTPError(
			http.StatusBadRequest,
			gud.NewErrorResponse("token validation failed:", err.Error()),
		)
	}

	if time.Now().After(claims.ExpiresAt.Time) {
		return c.JSON(http.StatusOK, "token expired")
	}

	return c.JSON(http.StatusNoContent, nil)
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
	accessToken, ok := c.Get("bearerToken").(string)

	if accessToken == "" || !ok {
		customErr := &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      "bearer token is required",
			InternalCode: constants.MISSING_BEARER_TOKEN,
		}
		return customErr
	}
	dto := &dtos.RenewTokensDTO{}
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

	sc := h.config.jwtSecret

	accessClaims, ok := c.Get("accessClaims").(*dtos.JwtCustomClaims)
	if !ok || accessClaims == nil {
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      "accessClaims is invalid or missing",
			InternalCode: "accessClaims:InvalidOrMissing:RenewTokens",
		}
	}

	refreshClaims, err := utils.ValidateJwt(dto.RefreshToken, sc)
	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      "refreshToken jwt token failed validation:" + err.Error(),
			InternalCode: "refreshToken:jwtValidationFailed:RenewTokens",
		}
	}
	// Check if the token can be refreshed
	if time.Now().After(refreshClaims.ExpiresAt.Time) {
		return &gut.CustomError{
			Code:         http.StatusBadRequest,
			Message:      "refresh token is expired, user should log in again",
			InternalCode: "refreshToken:Expired:RenewTokens",
		}
	}

	// Generate JWT token in auth-ms
	tokenArgs := &services.TokensGen{
		AccessToken: &services.TokenArgs{
			Claims:    accessClaims,
			ExpiresIn: accessExpiresIn,
		},
		RefreshToken: &services.TokenArgs{
			Claims:    refreshClaims,
			ExpiresIn: refreshExpiresIn,
		},
		Secret: h.config.jwtSecret,
	}

	access_token, refresh_token, err := tokenArgs.GenerateTokens()
	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      "token generation failed",
			InternalCode: "token:GenFailure:RenewTokens",
		}
	}
	user := new(models.UserCredentials)
	if err := h.UserCredentialsRepo.GetUserByEmail(user, accessClaims.Email); err != nil {
		return &gut.CustomError{
			Code:         http.StatusNotFound,
			Message:      err.Error(),
			InternalCode: "user:NotFound:RenewTokens",
		}
	}

	return c.JSON(
		http.StatusOK,
		dtos.TokenDTOResponse{
			Token:        access_token,
			RefreshToken: refresh_token,
			TokenExpires: time.Now().Add(accessExpiresIn),
			User:         *user.ToDto(),
		},
	)
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
	userProfID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			gud.NewErrorResponse("invalid id"),
		)
	}
	var user models.UserCredentials
	if err := h.UserCredentialsRepo.GetById(&user, userProfID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, gud.NewErrorResponse("user not found"))
		}
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			gud.NewErrorResponse("failed to retrieve user"),
		)
	}
	return c.JSON(http.StatusOK, user.ToDto())
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
	id := c.Param("user_id")
	UserCredentialsID, err := uuid.Parse(id)
	if err != nil {
		return echo.NewHTTPError(
			http.StatusBadRequest,
			gud.NewErrorResponse("invalid id ", err.Error()),
		)
	}
	if err := h.UserCredentialsRepo.GetById(&models.UserCredentials{}, UserCredentialsID); err != nil {
		if err == gorm.ErrRecordNotFound {
			return echo.NewHTTPError(http.StatusNotFound, gud.NewErrorResponse("user not found"))
		}
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			gud.NewErrorResponse("failed to retrieve user"),
		)
	}
	dto := dtos.UpdateUserCredentialsDTO{}
	// Bind the request body to the user struct
	if err := c.Bind(&dto); err != nil {
		return echo.NewHTTPError(
			http.StatusBadRequest,
			gud.NewErrorResponse("invalid request payload"),
		)
	}

	// Validate the user struct
	if err := c.Validate(&dto); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	user := &models.UserCredentials{
		UserId: UserCredentialsID,
	}

	if dto.Username != nil {
		user.Username = *dto.Username
	}

	if dto.Email != nil {
		user.Email = *dto.Email
	}

	if err := h.UserCredentialsRepo.Update(user); err != nil {
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			gud.NewErrorResponse("failed to update user"),
		)
	}

	return c.JSON(http.StatusOK, user.ToDto())
}

// GetAllUserCredentialss handles the request to retrieve all user profiles.
// @Summary Get all user profiles
// @Description Retrieve all user profiles
// @Produce json
// @Success 200 {array} models.UserCredentials
// @Failure 500 {object} gud.ErrorResponse
// @Router /user/profile [get]
func (h *AuthHandler) GetAllUserIdentities(c echo.Context) error {
	var users []models.UserCredentials
	if err := h.UserCredentialsRepo.GetAll(&users, c.Request()); err != nil {
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			gud.NewErrorResponse("failed to retrieve user profiles"),
		)
	}

	mapFunc := func(user models.UserCredentials) *dtos.UserCredentialsResponse {
		return user.ToDto()
	}
	return c.JSON(http.StatusOK, goutils.Map2(users, mapFunc))
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
	var user models.UserCredentials
	if err := h.UserCredentialsRepo.GetFirst(&user, "id = ?", actualUserId); err != nil {
		if err == gorm.ErrRecordNotFound {
			return echo.NewHTTPError(http.StatusNotFound, gud.NewErrorResponse("user not found"))
		}
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			gud.NewErrorResponse("failed to retrieve user"),
		)
	}
	if err := h.UserCredentialsRepo.Delete(&user, actualUserId); err != nil {
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			gud.NewErrorResponse("failed to delete user profile"),
		)
	}

	return c.NoContent(http.StatusNoContent)
}
