package models

import (
	"errors"
	"log"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Transfer interface {
	ToDto() any
}

// User represents a user profile.
type UserCredentials struct {
	gorm.Model

	UserId       uuid.UUID `gorm:"unique;not null;type:uuid;"`
	Username     string    `gorm:"unique;not null"                     json:"username"` // username is from the auth microservice
	Email        string    `gorm:"unique;not null"                     json:"email"`    // email is from the auth micro
	PasswordHash *[]byte   `                                           json:"passwordHash"`
	Role         string    `                                           json:"role"`
	Status       string    `                                           json:"status"`
	SocialId     *string   `gorm:"uniqueIndex:idx_social_id,omitempty" json:"socialId,omitempty"`
}

func (u *UserCredentials) Validate() error {
	if (u.SocialId == nil && u.PasswordHash == nil) ||
		(u.SocialId != nil && u.PasswordHash != nil) {
		return errors.New("either socialId or passwordHash must be filled, but not both")
	}
	return nil
}
func (up *UserCredentials) ToDto() *dtos.UserCredentialsResponse {
	log.Println("toDto", up)
	dto := &dtos.UserCredentialsResponse{
		ID:        up.ID,
		CreatedAt: up.CreatedAt.Local().UTC().String(),
		UpdatedAt: up.UpdatedAt.Local().UTC().String(),
		Email:     up.Email,
		Username:  up.Username,
		Role:      up.Role,
		Status:    up.Status,
		SocialId:  up.SocialId,
		UserId:    up.UserId,
	}

	return dto
}
