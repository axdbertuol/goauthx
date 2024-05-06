//go:build e2e_tests
// +build e2e_tests

package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/axdbertuol/goauthx/internal/dtos"
	"github.com/axdbertuol/goauthx/internal/handlers"
	internal_middleware "github.com/axdbertuol/goauthx/internal/middleware"
	"github.com/axdbertuol/goauthx/internal/models"
	"github.com/axdbertuol/goauthx/internal/services"
	"github.com/axdbertuol/goauthx/internal/utils"
	goutils "github.com/axdbertuol/goutils/functions"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/axdbertuol/goauthx/internal/repository"
	gum "github.com/axdbertuol/goutils/middleware"
)

var (
	e                 *echo.Echo
	db                *gorm.DB
	config            *viper.Viper
	password          = "Password123!"
	hashedPassword, _ = bcrypt.GenerateFromPassword([]byte(password), 1)
)

const (
	path = "/api/v1"
)

func TestMain(m *testing.M) {
	var (
		dsn string
	)
	ctx := context.Background()

	// Set up test database
	config = viper.GetViper()
	config.SetConfigFile("env-example")
	config.SetConfigType("env")
	config.ReadInConfig()

	_, ok := os.LookupEnv("CI")
	if ok {
		dbConnStr, err := goutils.GetConnection(config)
		if err != nil {
			panic(fmt.Errorf("failed to get connection: %v", err))
		}
		dsn = *dbConnStr
	} else {
		dbName := config.GetString("DATABASE_DBNAME")
		dbUser := config.GetString("DATABASE_USER")
		dbPassword := config.GetString("DATABASE_PASSWORD")

		postgresContainer, err := postgres.RunContainer(ctx,
			testcontainers.WithImage("docker.io/postgres:16-alpine"),
			postgres.WithInitScripts(filepath.Join("db", "init-e2e.sql")),
			// postgres.WithConfigFile(filepath.Join("testdata", "my-postgres.conf")),
			postgres.WithDatabase(dbName),
			postgres.WithUsername(dbUser),
			postgres.WithPassword(dbPassword),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(5*time.Second)),
		)
		if err != nil {
			log.Fatalf("failed to start container: %s", err)
		}
		dsn, err = postgresContainer.ConnectionString(ctx, "sslmode=disable")

		if err != nil {
			log.Fatalf("failed to start container: %s", err)
		}
		// Clean up the container
		defer func() {
			if err := postgresContainer.Terminate(ctx); err != nil {
				log.Fatalf("failed to terminate container: %s", err)
			}
		}()
	}

	newDb, err := goutils.ConnectToDb(
		dsn,
		goutils.OpenDatabaseConnection,
		0,
		1,
	)
	db = newDb
	if err != nil {
		log.Fatalf("failed to connect to test database: %v", err)
	}
	modelsList := []interface{}{
		&models.UserCredentials{},
	}

	// Run migrations
	if err := db.AutoMigrate(modelsList...); err != nil {
		log.Fatalf("failed to migrate: %v", err)
	}

	// db.Create(createUserCredentialsDTO)
	// if err := utils.Seed(db, false); err != nil {
	// 	panic("failed to seed database")
	// }
	// Set up Echo instance
	e = echo.New()
	// Middleware
	validator := validator.New()

	validator.RegisterValidation("password", internal_middleware.ValidatePassword)
	e.Validator = &gum.DefaultValidator{Validator: validator}
	// e.Use(middleware.Logger())
	// e.Use(middleware.Recover())
	e.Use(gum.ErrorMiddleware)

	// Initialize your handlers
	// Start repository
	userCredRepo := repository.NewUserCredentialsRepository(db)

	versionGroup := utils.CreateVersionedApiPath(e, "v1")

	// Start services
	authService := services.NewAuthService(userCredRepo, viper.GetViper())

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
	// Run tests
	exitVal := m.Run()

	// Clean up test data if needed
	if err := db.Migrator().DropTable(modelsList...); err != nil {
		panic("failed to drop table " + err.Error())
	}
	os.Exit(exitVal)
}

func TestGetAllUserCredentials_E2E(t *testing.T) {
	// Create a new HTTP request for GET /UserCredentials
	req := httptest.NewRequest(http.MethodGet, path+"/user-credentials", nil)

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
func TestCreateUserCredentialsWithEmail_E2E(t *testing.T) {
	// Create a sample login request body
	email := "test@example.com"
	signupRequest := dtos.CreateUserCredentialsDTO{
		UserId:       uuid.New(),
		Username:     "Teste",
		PasswordHash: hashedPassword,
		Email:        email,
		Status:       "inactive",
		Role:         "user",
	}

	// Marshal the request body to JSON
	signupRequestBody, err := json.Marshal(signupRequest)
	if err != nil {
		t.Fatalf("failed to marshal login request body: %v", err)
	}

	// Create a new HTTP request with the login request body
	req, err := http.NewRequest(
		"POST",
		path+"/user-credentials",
		bytes.NewBuffer(signupRequestBody),
	)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Set the Content-Type header to JSON
	req.Header.Set("Content-Type", "application/json")

	// Create a new HTTP recorder to record the response
	rec := httptest.NewRecorder()

	// Serve the request to the handler
	e.ServeHTTP(rec, req)

	// Check the response status code
	if rec.Code != http.StatusCreated {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rec.Code)
	}

	// Unmarshal the response body into a DTO
	var signupResponse dtos.UserCredentialsResponse
	err = json.Unmarshal(rec.Body.Bytes(), &signupResponse)
	if err != nil {
		t.Fatalf("failed to unmarshal login response body: %v", err)
	}

	// Assert that the access token is not empty
	assert.NotEmpty(t, signupResponse, "should not be empty")
	db.Exec("DELETE FROM user_credentials")

	// Add more assertions as needed to validate the response body
}

func TestLogin_E2E(t *testing.T) {
	// Create a signed-up user

	email := "logintest@example.com"
	CreateUserCredentialsDTO := dtos.CreateUserCredentialsDTO{
		Username:     "tester",
		Email:        email,
		PasswordHash: hashedPassword,
		Status:       "inactive",
		Role:         "user",
	}
	ucreds := &models.UserCredentials{
		UserId:       uuid.New(),
		Username:     "tester",
		Email:        email,
		Status:       "inactive",
		Role:         "user",
		PasswordHash: &hashedPassword,
	}
	err := db.Create(ucreds).Error
	assert.NoError(t, err)
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
	db.Exec("DELETE FROM user_credentials")
	// Create a user and get their tokens
	email := "testReftoken@example.com"
	password := "Password123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 1)

	CreateUserCredentialsDTO := dtos.CreateUserCredentialsDTO{
		Username:     "tester",
		Email:        email,
		PasswordHash: hashedPassword,
		Status:       "inactive",
		Role:         "user",
	}
	ucreds := &models.UserCredentials{
		UserId:       uuid.New(),
		Username:     "tester",
		Email:        email,
		Status:       "inactive",
		Role:         "user",
		PasswordHash: &hashedPassword,
	}
	err := db.Create(ucreds).Error
	assert.NoError(t, err)

	// Create a new user
	// RegisterUser(t, CreateUserCredentialsDTO)
	// Login and get tokens
	tokens := LoginAndAssert(t, dtos.LoginDTO{
		Username: &CreateUserCredentialsDTO.Username,
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
