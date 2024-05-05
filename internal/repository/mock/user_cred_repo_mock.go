package mock_repository

import (
	"net/http"

	"github.com/axdbertuol/goauthx/internal/models"
	"github.com/axdbertuol/goauthx/internal/repository"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

type MockStorableUserCredentialsRepository struct {
	repository.StorableUserCredentialsRepository
	mock.Mock
}

func (m *MockStorableUserCredentialsRepository) GetDb() *gorm.DB {
	args := m.Called()
	if len(args) > 0 {
		return args.Get(0).(*gorm.DB)
	}
	// Return a default value or handle the case where no arguments are provided
	return nil
}

// GetAll is a mocked implementation of the GetAll method.
func (m *MockStorableUserCredentialsRepository) GetAll(
	entities interface{},
	req *http.Request,
) error {
	args := m.Called(entities, req)
	return args.Error(0)
}

// GetByName is a mocked implementation of the GetByName method.
func (m *MockStorableUserCredentialsRepository) GetByName(
	entities interface{},
	name string,
	req *http.Request,
) error {
	args := m.Called(entities, name, req)
	return args.Error(0)
}

// GetById is a mocked implementation of the GetById method.
func (m *MockStorableUserCredentialsRepository) GetById(entity interface{}, id interface{}) error {
	args := m.Called(entity, id)
	return args.Error(0)
}

// Create is a mocked implementation of the Create method.
func (m *MockStorableUserCredentialsRepository) Create(entity interface{}) error {
	args := m.Called(entity)
	return args.Error(0)
}

// Update is a mocked implementation of the Update method.
func (m *MockStorableUserCredentialsRepository) Update(entity interface{}) error {
	args := m.Called(entity)
	return args.Error(0)
}

// Delete is a mocked implementation of the Delete method.
func (m *MockStorableUserCredentialsRepository) Delete(entity interface{}, id interface{}) error {
	args := m.Called(entity, id)
	return args.Error(0)
}

// ApplyPagination is a mocked implementation of the ApplyPagination method.
// func (m *MockStorableUserCredentialsRepository) ApplyPagination(req *http.Request) *gorm.DB {
// 	args := m.Called(req)
// 	return args.Get(0).(*gorm.DB)
// }

func (m *MockStorableUserCredentialsRepository) GetUserByEmail(
	user *models.UserCredentials,
	email string,
) error {
	args := m.Called(user, email)
	return args.Error(0)
}

func (m *MockStorableUserCredentialsRepository) GetUserByUsername(
	user *models.UserCredentials,
	username string,
) error {
	args := m.Called(user, username)
	return args.Error(0)
}

func (m *MockStorableUserCredentialsRepository) GetFirst(
	user *models.UserCredentials,
	conds ...interface{},
) error {
	args := m.Called(user, conds)
	return args.Error(0)
}
func (m *MockStorableUserCredentialsRepository) UpdatePassword(user *models.UserCredentials) error {
	args := m.Called(user)
	return args.Error(0)
}
func (m *MockStorableUserCredentialsRepository) GetUserWithToken(
	user *models.UserCredentials,
	entityName string,
	conds ...interface{},
) error {
	args := m.Called(user, entityName, conds)
	return args.Error(0)
}
