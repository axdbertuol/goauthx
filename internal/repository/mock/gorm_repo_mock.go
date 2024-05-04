// mock_repository_test.go
package mock_repository

import (
	"net/http"

	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// MockGormRepository is a mock implementation of the GormRepository struct.
type MockGormRepository struct {
	mock.Mock
}

// GetAll is a mocked implementation of the GetAll method.
func (m *MockGormRepository) GetAll(entities interface{}, req *http.Request) error {
	args := m.Called(entities, req)
	return args.Error(0)
}

// GetByName is a mocked implementation of the GetByName method.
func (m *MockGormRepository) GetByName(entities interface{}, name string, req *http.Request) error {
	args := m.Called(entities, name, req)
	return args.Error(0)
}

// GetById is a mocked implementation of the GetById method.
func (m *MockGormRepository) GetById(entity interface{}, id uint) error {
	args := m.Called(entity, id)
	return args.Error(0)
}

// Create is a mocked implementation of the Create method.
func (m *MockGormRepository) Create(entity interface{}) error {
	args := m.Called(entity)
	return args.Error(0)
}

// Update is a mocked implementation of the Update method.
func (m *MockGormRepository) Update(entity interface{}) error {
	args := m.Called(entity)
	return args.Error(0)
}

// Delete is a mocked implementation of the Delete method.
func (m *MockGormRepository) Delete(entity interface{}, id uint) error {
	args := m.Called(entity, id)
	return args.Error(0)
}

// ApplyPagination is a mocked implementation of the ApplyPagination method.
func (m *MockGormRepository) ApplyPagination(req *http.Request) *gorm.DB {
	args := m.Called(req)
	return args.Get(0).(*gorm.DB)
}
func (m *MockGormRepository) Save(
	entity interface{},
) error {
	args := m.Called(entity)
	return args.Error(0)
}
