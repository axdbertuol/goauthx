package services

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	gud "github.com/axdbertuol/goutils/dtos"
	goutils "github.com/axdbertuol/goutils/functions"
	gut "github.com/axdbertuol/goutils/types"
	"github.com/google/uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/idtoken"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/axdbertuol/goauthx/internal/models"
	"github.com/axdbertuol/goauthx/internal/repository"
	"github.com/axdbertuol/goauthx/internal/utils"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type AuthServicer interface {
	UpdateUserCredentials(
		ucreds *models.UserCredentials,
		dto *dtos.UpdateUserCredentialsDTO,
	) error
	GetAllUserCredentials(
		req *http.Request,
	) ([]dtos.UserCredentialsResponse, error)
	CreateUserCredentials(
		ucreds *models.UserCredentials,
		dto *dtos.CreateUserCredentialsDTO,
	) error
	GetUserCredentialsByID(
		ucreds *models.UserCredentials,
		string uuid.UUID,
	) error
	DeleteUserCredentials(userId uint) error
	SignInWithGoogle(
		tokenResp *dtos.TokenDTOResponse,
		dto *dtos.LoginGoogleDTO,
	) error
	Login(
		tokenResp *dtos.TokenDTOResponse,
		dto *dtos.LoginDTO,
	) error
	RenewTokens(
		tokenResp *dtos.TokenDTOResponse,
		dto *dtos.RenewTokensDTO,
		accessClaims *dtos.JwtCustomClaims,
	) error
}

const (
	accessExpiresIn  = 1 * time.Minute
	refreshExpiresIn = 24 * time.Hour
)

type AuthConfig struct {
	jwtSecret string
}

type AuthService struct {
	AuthServicer
	userCredRepo repository.StorableUserCredentialsRepository
	config       *AuthConfig
}

func NewAuthService(
	userCredRepo repository.StorableUserCredentialsRepository,
	config *viper.Viper,
) AuthServicer {
	secret := config.GetString("JWT_SECRET")
	return &AuthService{
		userCredRepo: userCredRepo,
		config:       &AuthConfig{jwtSecret: secret},
	}
}

func (as *AuthService) UpdateUserCredentials(
	ucreds *models.UserCredentials,
	dto *dtos.UpdateUserCredentialsDTO,
) error {
	var (
		selected = []string{}
	)

	if err := as.userCredRepo.GetById(&models.UserCredentials{}, dto.UserId); err != nil {
		if err == gorm.ErrRecordNotFound {
			return echo.NewHTTPError(http.StatusNotFound, gud.NewErrorResponse("user not found"))
		}
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			gud.NewErrorResponse("failed to retrieve user"),
		)
	}
	ucreds.UserId = dto.UserId
	if dto.Username != nil {
		ucreds.Username = *dto.Username
		selected = append(selected, "username")
	}
	if dto.Email != nil {
		ucreds.Email = *dto.Email
		selected = append(selected, "email")
	}
	if dto.Role != nil {
		ucreds.Role = *dto.Role
		selected = append(selected, "role")
	}
	if dto.Status != nil {
		ucreds.Status = *dto.Status
		selected = append(selected, "status")
	}
	if dto.SocialId != nil {
		ucreds.SocialId = dto.SocialId
		selected = append(selected, "social_id")
	}
	if dto.PasswordHash != nil {
		ucreds.PasswordHash = dto.PasswordHash
		selected = append(selected, "password_hash")
	}
	// oh.logger.Info(fmt.Sprintf("%+v", ucreds))
	if err := as.userCredRepo.UpdateUserCredentials(ucreds, &selected); err != nil {
		slog.Error("error creating user for event %v", err)
		return err
	}
	return nil
}

func (as *AuthService) CreateUserCredentials(
	ucreds *models.UserCredentials,
	dto *dtos.CreateUserCredentialsDTO,
) error {
	ucreds.Username = dto.Username
	ucreds.Email = dto.Email
	ucreds.Role = dto.Role
	ucreds.Status = dto.Status
	ucreds.UserId = dto.UserId

	if dto.PasswordHash != nil {
		ucreds.PasswordHash = &dto.PasswordHash
	}
	if dto.SocialId != "" {
		ucreds.SocialId = &dto.SocialId
	}

	// Create user in the database
	if err := as.userCredRepo.Create(ucreds); err != nil {
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
	return nil
}

func (as *AuthService) SignInWithGoogle(
	tokenResp *dtos.TokenDTOResponse,
	dto *dtos.LoginGoogleDTO,
) error {

	ucreds := new(models.UserCredentials)
	payload, err := idtoken.Validate(
		context.Background(),
		dto.IdToken,
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
	if err := as.userCredRepo.
		GetFirst(ucreds, "social_id = ?", &payload.Subject); err != nil {
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
		UserId:   ucreds.UserId,
		Username: ucreds.Username,
		Email:    ucreds.Email,
		Role:     ucreds.Role,
	}
	args := &TokensGen{
		AccessToken: &TokenArgs{
			User:      jwtGenDto,
			ExpiresIn: accessExpiresIn,
			RegClaims: regClaims,
		},
		RefreshToken: &TokenArgs{
			User:      jwtGenDto,
			ExpiresIn: refreshExpiresIn,
			RegClaims: regClaims,
		},
		Secret: as.config.jwtSecret,
	}

	accessToken, refreshToken, err := args.GenerateTokens()
	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      err.Error(),
			InternalCode: "token:GenFailure:google",
		}
	}

	tokenResp.Token = accessToken
	tokenResp.RefreshToken = refreshToken
	tokenResp.TokenExpires = time.Now().Add(accessExpiresIn)
	tokenResp.User = *ucreds.ToDto()

	return nil

}

func (as *AuthService) Login(tokenResp *dtos.TokenDTOResponse, dto *dtos.LoginDTO) error {
	ucreds := new(models.UserCredentials)
	if dto.Email != nil {
		// Retrieve user by username
		err := as.userCredRepo.GetUserByEmail(ucreds, *dto.Email)
		if err != nil {
			return &gut.CustomError{
				Code:         http.StatusUnauthorized,
				Message:      err.Error(),
				InternalCode: "email:InvalidCredentials:login",
			}
		}
	} else if dto.Username != nil {
		err := as.userCredRepo.GetUserByUsername(ucreds, *dto.Username)
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

	if err := bcrypt.CompareHashAndPassword(*ucreds.PasswordHash, []byte(dto.Password)); err != nil {
		return &gut.CustomError{
			Code:         http.StatusUnauthorized,
			Message:      err.Error(),
			InternalCode: "password:InvalidCredentials:login",
		}
	}

	jwtGenDto := &dtos.JwtGenDTO{
		UserId:   ucreds.UserId,
		Username: ucreds.Username,
		Email:    ucreds.Email,
		Role:     ucreds.Role,
	}

	tokenArgs := &TokensGen{
		AccessToken: &TokenArgs{
			User:      jwtGenDto,
			ExpiresIn: accessExpiresIn,
		},
		RefreshToken: &TokenArgs{
			User:      jwtGenDto,
			ExpiresIn: refreshExpiresIn,
		},
		Secret: as.config.jwtSecret,
	}

	accessToken, refreshToken, err := tokenArgs.GenerateTokens()

	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      "failed to generate tokens: " + err.Error(),
			InternalCode: "token:GenFailure:login",
		}
	}

	tokenResp.Token = accessToken
	tokenResp.RefreshToken = refreshToken
	tokenResp.TokenExpires = time.Now().Add(accessExpiresIn)
	tokenResp.User = *ucreds.ToDto()

	return nil
}

func (as *AuthService) RenewTokens(
	tokenResp *dtos.TokenDTOResponse,
	dto *dtos.RenewTokensDTO,
	accessClaims *dtos.JwtCustomClaims,
) error {
	secret := as.config.jwtSecret

	refreshClaims, err := utils.ValidateJwt(dto.RefreshToken, secret)
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
	tokenArgs := &TokensGen{
		AccessToken: &TokenArgs{
			Claims:    accessClaims,
			ExpiresIn: accessExpiresIn,
		},
		RefreshToken: &TokenArgs{
			Claims:    refreshClaims,
			ExpiresIn: refreshExpiresIn,
		},
		Secret: secret,
	}

	newAccessToken, newRefreshToken, err := tokenArgs.GenerateTokens()
	if err != nil {
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      "token generation failed",
			InternalCode: "token:GenFailure:RenewTokens",
		}
	}
	ucreds := new(models.UserCredentials)
	if err := as.userCredRepo.GetUserByEmail(ucreds, accessClaims.Email); err != nil {
		return &gut.CustomError{
			Code:         http.StatusNotFound,
			Message:      err.Error(),
			InternalCode: "userCredentials:NotFound:RenewTokens",
		}
	}

	tokenResp.Token = newAccessToken
	tokenResp.RefreshToken = newRefreshToken
	tokenResp.TokenExpires = time.Now().Add(accessExpiresIn)
	tokenResp.User = *ucreds.ToDto()

	return nil
}
func (as *AuthService) GetUserCredentialsByID(
	ucreds *models.UserCredentials,
	userId uuid.UUID,
) error {
	if err := as.userCredRepo.GetById(ucreds, userId); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &gut.CustomError{
				Code:         http.StatusNotFound,
				Message:      err.Error(),
				InternalCode: "userCredentials:NotFound:GetUserCredentialsByID",
			}
		}
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      err.Error(),
			InternalCode: ":UnknownError:GetUserCredentialsByID",
		}
	}
	return nil
}

func (as *AuthService) GetAllUserCredentials(
	req *http.Request,
) ([]dtos.UserCredentialsResponse, error) {
	ucreds := []models.UserCredentials{}
	if err := as.userCredRepo.GetAll(&ucreds, req); err != nil {
		return nil, &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      err.Error(),
			InternalCode: ":UnknownError:GetAllUserCredentials",
		}
	}

	mapFunc := func(user models.UserCredentials) dtos.UserCredentialsResponse {
		return *user.ToDto()
	}
	mappedCreds := goutils.Map2(ucreds, mapFunc)
	return mappedCreds, nil
}

func (as *AuthService) DeleteUserCredentials(userId uint) error {
	if err := as.userCredRepo.Delete(new(models.UserCredentials), userId); err != nil {
		if err == gorm.ErrRecordNotFound {
			return &gut.CustomError{
				Code:         http.StatusNotFound,
				Message:      err.Error(),
				InternalCode: "userCredentials:NotFound:DeleteUserCredentials",
			}
		}
		return &gut.CustomError{
			Code:         http.StatusInternalServerError,
			Message:      err.Error(),
			InternalCode: ":UnknownFailure:DeleteUserCredentials",
		}
	}
	return nil
}
