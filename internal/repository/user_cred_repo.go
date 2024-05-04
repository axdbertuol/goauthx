package repository

import (
	"github.com/axdbertuol/auth_service/internal/models"
	"gorm.io/gorm"
)

type StorableUserCredentialsRepository interface {
	StorableRepository
	GetDb() *gorm.DB
	GetUserByUsername(user *models.UserCredentials, username string) error
	GetUserByEmail(user *models.UserCredentials, email string) error
	GetFirst(user *models.UserCredentials, conds ...interface{}) error
	GetUserWithToken(entity *models.UserCredentials, entityName string, conds ...interface{}) error
	UpdatePassword(user *models.UserCredentials) error
}
type UserCredentialsRepository struct {
	GormRepository
}

func NewUserCredentialsRepository(db *gorm.DB) StorableUserCredentialsRepository {
	gr := &GormRepository{Db: db}
	return &UserCredentialsRepository{GormRepository: *gr}
}

func (u *UserCredentialsRepository) GetDb() *gorm.DB {
	return u.Db
}

func (ur *UserCredentialsRepository) GetUserByEmail(
	user *models.UserCredentials,
	email string,
) error {

	if err := ur.Db.First(user, "email = ?", email).Error; err != nil {
		return err
	}
	return nil
}

func (ur *UserCredentialsRepository) GetUserByUsername(
	user *models.UserCredentials,
	username string,
) error {
	if err := ur.Db.First(user, "username = ?", username).Error; err != nil {
		return err
	}
	return nil
}

func (ur *UserCredentialsRepository) GetFirst(
	user *models.UserCredentials,
	conds ...interface{},
) error {
	if err := ur.Db.First(user, conds...).Error; err != nil {
		return err
	}
	return nil
}

func (ur *UserCredentialsRepository) UpdatePassword(user *models.UserCredentials) error {
	if err := ur.Db.Model(user).Select("PasswordHash").Updates(user).Error; err != nil {
		return err
	}
	return nil
}

func (ur *UserCredentialsRepository) GetUserWithToken(
	user *models.UserCredentials,
	entityName string,
	conds ...interface{},
) error {
	if err := ur.Db.Preload(entityName).First(user, conds...).Error; err != nil {
		return err
	}
	return nil
}
