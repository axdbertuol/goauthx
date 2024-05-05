package dtos

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type UpdateUserCredentialsDTO struct {
	UserId       uuid.UUID `json:"userId"                 validate:"required"`
	Username     *string   `json:"username,omitempty"     validate:"omitempty"`
	Email        *string   `json:"email,omitempty"        validate:"omitempty,email"`
	PasswordHash *[]byte   `json:"passwordHash,omitempty" validate:"omitempty"`
	Status       *string   `json:"status,omitempty"       validate:"omitempty"`
	Role         *string   `json:"role,omitempty"         validate:"omitempty"`
	SocialId     *string   `json:"socialId,omitempty"     validate:"omitempty"`
}

type UserCredentialsResponse struct {
	ID        uint      `json:"id"`
	CreatedAt string    `json:"createdAt"`
	UpdatedAt string    `json:"updatedAt"`
	DeletedAt string    `json:"deletedAt"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Username  string    `json:"username"`
	SocialId  *string   `json:"socialId"`
	Status    string    `json:"status"`
	UserId    uuid.UUID `json:"userId"`
}

type CreateUserCredentialsDTO struct {
	UserId       uuid.UUID `json:"userId"                 validate:"required"`
	Username     string    `json:"username"               validate:"required"`
	Email        string    `json:"email"                  validate:"required,email"`
	PasswordHash []byte    `json:"passwordHash,omitempty" validate:"omitempty,required_without=SocialId"`
	Status       string    `json:"status"                 validate:"required"`
	Role         string    `json:"role"                   validate:"required"`
	SocialId     string    `json:"socialId,omitempty"     validate:"omitempty,required_without=PasswordHash"`
}

func (u *CreateUserCredentialsDTO) BindAndValidate(c echo.Context) error {
	return BindAndValidate(u, c)
}

type LoginGoogleDTO struct {
	IdToken string `json:"idToken" validate:"required"`
}

func (u *LoginGoogleDTO) BindAndValidate(c echo.Context) error {
	return BindAndValidate(u, c)
}

type LoginDTO struct {
	Username *string `json:"username,omitempty" validate:"omitnil,required_without=Email,min=5"`
	Email    *string `json:"email,omitempty"    validate:"omitnil,required_without=Username,email"`
	Password string  `json:"password"           validate:"required"`
}

func (u *LoginDTO) BindAndValidate(c echo.Context) error {
	return BindAndValidate(u, c)
}

type RenewTokensDTO struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type TokenDTOResponse struct {
	Token        string                  `json:"token"`
	RefreshToken string                  `json:"refreshToken"`
	TokenExpires time.Time               `json:"tokenExpires"`
	User         UserCredentialsResponse `json:"user"`
}

type JwtGenDTO struct {
	UserId   string `json:"userId"   validate:"required"`
	Username string `json:"username" validate:"required,min=5"`
	Email    string `json:"email"    validate:"required,email"`
	Role     string `json:"role"     validate:"required,oneof=user admin"`
}

func (u *JwtGenDTO) BindAndValidate(c echo.Context) error {
	return BindAndValidate(u, c)
}

type JwtCustomClaims struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}
