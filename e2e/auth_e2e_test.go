//go:build e2e_tests
// +build e2e_tests

package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/axdbertuol/goauthx/internal/handlers"
	internal_middleware "github.com/axdbertuol/goauthx/internal/middleware"
	gum "github.com/axdbertuol/goutils/middleware"
	testhelpers "github.com/axdbertuol/goutils/test_helpers"

	"github.com/axdbertuol/goauthx/internal/models"
	"github.com/axdbertuol/goauthx/internal/repository"
	"github.com/axdbertuol/goauthx/internal/services"
	"github.com/axdbertuol/goauthx/internal/utils"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	db                *gorm.DB
	config            *viper.Viper
	password          = "Password123!"
	hashedPassword, _ = bcrypt.GenerateFromPassword([]byte(password), 1)
	scase             *testhelpers.E2ESuitCase
)

const (
	path = "/api/v1"
)

func MustInitEcho(m *testing.M, e *echo.Echo) {

	// Middleware
	validator := validator.New()

	validator.RegisterValidation("password", internal_middleware.ValidatePassword)
	e.Validator = &gum.DefaultValidator{Validator: validator}
	// e.Use(middleware.Logger())
	// e.Use(middleware.Recover())
	e.Use(gum.ErrorMiddleware)

	// Start repository
	userCredRepo := repository.NewUserCredentialsRepository(scase.DB)

	versionGroup := utils.CreateVersionedApiPath(e, "v1")

	// Start services
	authService := services.NewAuthService(userCredRepo, config)

	// Initialize your handlers
	handlers.
		NewAuthHandler(authService).
		RegisterAuthRoutes(versionGroup, internal_middleware.BearerAuthMiddleware)
	go func() {
		// Start your Echo server
		if err := e.Start(":13333"); err != nil {
			log.Fatalf("failed to start server: %v", err)
		}
	}()
	defer e.Close()
	exitVal := m.Run()

	// Clean up test data if needed
	scase.Cleanup(modelsList...)
	os.Exit(exitVal)

}

var (
	e          *echo.Echo
	modelsList = []interface{}{
		&models.UserCredentials{},
	}
)

func TestMain(m *testing.M) {

	ctx := context.Background()
	e = echo.New()
	// Set up test database
	config = viper.GetViper()
	config.SetConfigFile("../env-example")
	config.SetConfigType("env")
	config.ReadInConfig()

	scase = &testhelpers.E2ESuitCase{
		Ctx:        ctx,
		Config:     config,
		ScriptPath: "./init-e2e.sql",
	}
	scase.MustInitEnvironment()
	defer func() {
		if err := scase.PgContainer.Terminate(ctx); err != nil {
			log.Fatalf("failed to terminate container: %s", err)
		}
	}()
	scase.Setup(modelsList...)
	MustInitEcho(m, e)

}

func TestCreateUserCredentialsWithEmail_E2E(t *testing.T) {
	// Create a sample login request bodyc
	scase.Cleanup(modelsList...)
	scase.Setup(modelsList...)
	email := "test@example.com"
	dto := dtos.CreateUserCredentialsDTO{
		UserId:       uint(123),
		Username:     "Teste",
		PasswordHash: hashedPassword,
		Email:        email,
		Status:       "inactive",
		Role:         "user",
	}

	// Marshal the request body to JSON
	signupRequestBody, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("failed to marshal login request body: %v", err)
	}

	// Create a new HTTP request with the login request body
	req := httptest.NewRequest(
		http.MethodPost,
		path+"/register",
		bytes.NewBuffer(signupRequestBody),
	)

	// Set the Content-Type header to JSON
	req.Header.Set("Content-Type", "application/json")

	// Create a new HTTP recorder to record the response
	rec := httptest.NewRecorder()

	// Serve the request to the handler
	e.ServeHTTP(rec, req)

	// Check the response status code
	if rec.Code != http.StatusCreated {
		t.Errorf("expected status code %d, got %d", http.StatusCreated, rec.Code)
	}

	// Unmarshal the response body into a DTO
	var signupResponse dtos.UserCredentialsResponse
	err = json.Unmarshal(rec.Body.Bytes(), &signupResponse)
	if err != nil {
		t.Fatalf("failed to unmarshal login response body: %v", err)
	}

	// Assert that the access token is not empty
	assert.NotEmpty(t, signupResponse, "should not be empty")
	// db.Exec("DELETE FROM user_credentials")

	// Add more assertions as needed to validate the response body
}
func TestGetAllUserCredentials_E2E(t *testing.T) {
	scase.Cleanup(modelsList...)
	scase.Setup(modelsList...)

	// Create a new HTTP request for GET /UserCredentials
	req := httptest.NewRequest(http.MethodGet, path+"/credentials", nil)

	// Create a new HTTP recorder
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	// Check the response status code
	if rec.Code != http.StatusOK {
		t.Errorf("expected status code 200, got %d", rec.Code)
	}

	// Validate content type of the response
	contentType := rec.Header().Get("Content-Type")
	assert.Contains(t, contentType, "application/json")

	// Parse response body as JSON
	var UserCredentialss []dtos.UserCredentialsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &UserCredentialss); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}

	// Add assertions to validate the response body
}
func TestLogin_E2E(t *testing.T) {
	scase.Cleanup(modelsList...)
	scase.Setup(modelsList...)

	email := "logintest@example.com"
	CreateUserCredentialsDTO := dtos.CreateUserCredentialsDTO{
		Username:     "tester",
		Email:        email,
		PasswordHash: hashedPassword,
		Status:       "inactive",
		Role:         "user",
	}
	ucreds := models.UserCredentials{
		UserId:       uint(123),
		Username:     "tester",
		Email:        email,
		Status:       "inactive",
		Role:         "user",
		PasswordHash: &hashedPassword,
		SocialId:     nil,
	}
	err := scase.CreateEntities(&ucreds)
	assert.NotErrorIs(t, err, gorm.ErrDuplicatedKey)
	// Register the user
	// RegisterUser(t, CreateUserCredentialsDTO)

	// Subtest for successful login with email
	t.Run("LoginWithEmail", func(t *testing.T) {
		LoginAndAssert(t, dtos.LoginDTO{Email: &email, Password: password})
	})

	// Subtest for successful login with username
	t.Run("LoginWithUsername", func(t *testing.T) {
		LoginAndAssert(
			t,
			dtos.LoginDTO{Username: &CreateUserCredentialsDTO.Username, Password: password},
		)
	})

	// Subtest for failed login with incorrect password
	t.Run("LoginWithIncorrectPassword", func(t *testing.T) {
		// Try to login with incorrect password
		loginRequest := dtos.LoginDTO{Email: &email, Password: "incorrectPassword"}
		loginRequestBody, err := json.Marshal(loginRequest)
		assert.NoError(t, err)

		// Create a new HTTP request with the login request body
		req, err := http.NewRequest("POST", path+"/login", bytes.NewBuffer(loginRequestBody))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		// Create a new HTTP recorder to record the response
		rec := httptest.NewRecorder()

		// Serve the request to the handler
		e.ServeHTTP(rec, req)

		// Check the response status code
		assert.Equal(
			t,
			http.StatusUnauthorized,
			rec.Code,
			"expected status code 401 for failed login",
		)

		// Optionally, you can validate the response body here
	})

	// Add more subtests as needed
}
func TestRefreshToken_E2E(t *testing.T) {

	// Clean up any existing email confirm tokens and user profiles in the database
	scase.Cleanup(modelsList...)
	scase.Setup(modelsList...)

	// Create a user and get their tokens
	email := "testReftoken@example.com"
	password := "Password123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 1)

	createUserCredentialsDTO := dtos.CreateUserCredentialsDTO{
		Username:     "tester",
		Email:        email,
		PasswordHash: hashedPassword,
		Status:       "inactive",
		Role:         "user",
	}
	ucreds := &models.UserCredentials{
		UserId:       uint(123),
		Username:     "tester",
		Email:        email,
		Status:       "inactive",
		Role:         "user",
		PasswordHash: &hashedPassword,
	}
	err := scase.CreateEntities(ucreds)
	assert.NoError(t, err)

	// Create a new user
	// RegisterUser(t, CreateUserCredentialsDTO)
	// Login and get tokens
	tokens := LoginAndAssert(t, dtos.LoginDTO{
		Username: &createUserCredentialsDTO.Username,
		Password: password,
	})

	// Construct the refresh token request
	t.Run("RefreshToken", func(t *testing.T) {
		reqBody, err := json.Marshal(dtos.RenewTokensDTO{RefreshToken: tokens.RefreshToken})
		assert.NoError(t, err)
		req, err := http.NewRequest(
			"POST",
			path+"/renew-tokens",
			bytes.NewBuffer(reqBody),
		)
		req.Header.Set("Authorization", "Bearer "+tokens.Token)
		req.Header.Set("Content-Type", "application/json")

		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		// Create a new HTTP recorder to record the response
		rec := httptest.NewRecorder()

		// Serve the request to the handler
		e.ServeHTTP(rec, req)

		// Check the response status code
		if rec.Code != http.StatusOK {
			t.Errorf("expected status code %d, got %d", http.StatusOK, rec.Code)
		}

		// Unmarshal the response body into a DTO
		var refreshResponse dtos.TokenDTOResponse
		err = json.Unmarshal(rec.Body.Bytes(), &refreshResponse)
		if err != nil {
			t.Fatalf("failed to unmarshal refresh token response body: %v", err)
		}

		// Assert that the access token is not empty
		assert.NotEmpty(t, refreshResponse.Token, "access token should not be empty")
	})

	// TestExpiredRefreshToken
	t.Run("ExpiredRefreshToken", func(t *testing.T) {
		reqBody, err := json.Marshal(dtos.RenewTokensDTO{RefreshToken: tokens.RefreshToken})
		assert.NoError(t, err)
		req, err := http.NewRequest(
			"POST",
			path+"/renew-tokens",
			bytes.NewBuffer(reqBody),
		)
		req.Header.Set("Authorization", "Bearer "+tokens.Token)
		req.Header.Set("Content-Type", "application/json")

		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		// Create a new HTTP recorder to record the response
		rec := httptest.NewRecorder()

		// Serve the request to the handler
		e.ServeHTTP(rec, req)

		// Check the response status code
		if rec.Code != http.StatusOK {
			t.Errorf("expected status code %d, got %d", http.StatusOK, rec.Code)
		}

		// Unmarshal the response body into a DTO
		var refreshResponse dtos.TokenDTOResponse
		err = json.Unmarshal(rec.Body.Bytes(), &refreshResponse)
		if err != nil {
			t.Fatalf("failed to unmarshal refresh token response body: %v", err)
		}

		// Assert that the access token is not empty
		assert.NotEmpty(t, refreshResponse.Token, "access token should not be empty")
	})

	// TestInvalidRefreshToken
	t.Run("InvalidRefreshToken", func(t *testing.T) {
		// Prepare necessary data and context
		// Call RenewTokens method
		// Assert the expected behavior
	})

	// TestTokenGenerationFailure
	t.Run("TokenGenerationFailure", func(t *testing.T) {
		// Prepare necessary data and context
		// Call RenewTokens method
		// Assert the expected behavior
	})

	// TestUserNotFound
	t.Run("UserNotFound", func(t *testing.T) {
		// Prepare necessary data and context
		// Call RenewTokens method
		// Assert the expected behavior
	})
}

// func TestEndToEndCases(t *testing.T) {
// 	ucred1 := &models.UserCredentials{
// 		Model:        gorm.Model{ID: 1},
// 		UserId:       uint(123),
// 		Username:     "testuser",
// 		Email:        "testuser@example.com",
// 		PasswordHash: &hashedPassword,
// 		Role:         "user",
// 		Status:       "inactive",
// 		SocialId:     nil,
// 	}
// 	ucredDto := ucred1.ToDto()
// 	ucredLogin := &dtos.LoginDTO{
// 		Username: &ucred1.Username,
// 		Email:    &ucred1.Email,
// 		Password: password,
// 	}
// 	// if err := testhelpers.Setup(scase.DB, ucred1); err != nil {
// 	// 	log.Fatal(err)
// 	// }

// 	testCases := []struct {
// 		name            string
// 		method          string
// 		path            string
// 		body            interface{}
// 		runAfter        func(...any) any
// 		expectedStatus  int
// 		expectedContent string
// 	}{

// 		{
// 			name:           "CreateUserCredentialsWithEmail",
// 			method:         http.MethodPost,
// 			path:           path + "/credentials",
// 			body:           ucredDto,
// 			expectedStatus: http.StatusCreated,
// 			// Add expected content if needed
// 		},
// 		{
// 			name:           "GetAllUserCredentials",
// 			method:         http.MethodGet,
// 			path:           path + "/credentials",
// 			body:           nil,
// 			expectedStatus: http.StatusOK,
// 			// Add expected content if needed
// 		},
// 		{
// 			name:           "Login",
// 			method:         http.MethodPost,
// 			path:           path + "/login",
// 			body:           ucredLogin,
// 			expectedStatus: http.StatusOK,
// 			// Add expected content if needed
// 		},
// 		{
// 			name:           "RefreshToken",
// 			method:         http.MethodPost,
// 			path:           path + "/renew-tokens",
// 			body:           dtos.RenewTokensDTO{ /* Populate with necessary fields */ },
// 			expectedStatus: http.StatusOK,
// 			// Add expected content if needed
// 		},
// 		// Add more test cases as needed
// 	}

// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			// Create a new HTTP request
// 			var req *http.Request
// 			var err error
// 			if tc.body != nil {
// 				bodyBytes, err := json.Marshal(tc.body)
// 				if err != nil {
// 					t.Fatalf("failed to marshal request body: %v", err)
// 				}
// 				req, err = http.NewRequest(tc.method, tc.path, bytes.NewBuffer(bodyBytes))
// 			} else {
// 				req, err = http.NewRequest(tc.method, tc.path, nil)
// 			}
// 			if err != nil {
// 				t.Fatalf("failed to create request: %v", err)
// 			}

// 			// Create a new HTTP recorder to record the response
// 			rec := httptest.NewRecorder()

// 			// Serve the request to the handler
// 			e.ServeHTTP(rec, req)

// 			// Check the response status code
// 			if rec.Code != tc.expectedStatus {
// 				t.Errorf("expected status code %d, got %d", tc.expectedStatus, rec.Code)
// 			}

// 			// Optionally, validate the response body here
// 		})
// 	}
// }

// Helper function to register a user
func RegisterUser(t *testing.T, CreateUserCredentialsDTO dtos.CreateUserCredentialsDTO) {
	// Marshal the request body to JSON
	requestBody, err := json.Marshal(CreateUserCredentialsDTO)
	assert.NoError(t, err)

	// Create a new HTTP request with the request body
	req, err := http.NewRequest("POST", path+"/register", bytes.NewBuffer(requestBody))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Create a new HTTP recorder to record the response
	rec := httptest.NewRecorder()

	// Serve the request to the handler
	e.ServeHTTP(rec, req)

	// Check the response status code
	assert.Equal(
		t,
		http.StatusCreated,
		rec.Code,
		"expected status code 201 for successful registration",
	)
}

// Helper function to login and assert the response
func LoginAndAssert(t *testing.T, loginDTO dtos.LoginDTO) dtos.TokenDTOResponse {
	// Marshal the request body to JSON
	requestBody, err := json.Marshal(loginDTO)
	assert.NoError(t, err)

	// Create a new HTTP request with the request body
	req, err := http.NewRequest("POST", path+"/login", bytes.NewBuffer(requestBody))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Create a new HTTP recorder to record the response
	rec := httptest.NewRecorder()

	// Serve the request to the handler
	e.ServeHTTP(rec, req)

	// Check the response status code
	assert.Equal(t, http.StatusOK, rec.Code, "expected status code 200 for successful login")

	// Unmarshal the response body into a DTO
	var loginResponse dtos.TokenDTOResponse
	err = json.Unmarshal(rec.Body.Bytes(), &loginResponse)
	assert.NoError(t, err)

	// Assert that the access token is not empty
	assert.NotEmpty(t, loginResponse.Token, "access token should not be empty")
	return loginResponse
}
