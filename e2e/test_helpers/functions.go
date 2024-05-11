//go:build e2e_tests
// +build e2e_tests

package testhelpers

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/axdbertuol/goauthx/internal/handlers"
	internal_middleware "github.com/axdbertuol/goauthx/internal/middleware"
	"github.com/axdbertuol/goauthx/internal/models"
	"github.com/axdbertuol/goauthx/internal/repository"
	"github.com/axdbertuol/goauthx/internal/services"
	"github.com/axdbertuol/goauthx/internal/utils"
	goutils "github.com/axdbertuol/goutils/functions"
	gum "github.com/axdbertuol/goutils/middleware"
	"gorm.io/gorm"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

type E2ESuitCase struct {
	Ctx        context.Context
	Config     *viper.Viper
	ScriptPath string
	Echo       *echo.Echo
	DB         *gorm.DB
}

func (esc *E2ESuitCase) InitE2E(m *testing.M) {
	var (
		dsn    string
		config = esc.Config
		ctx    = esc.Ctx
		e      = echo.New()
	)
	_, ok := os.LookupEnv("CI")
	if ok {
		dbConnStr, err := goutils.GetConnection(config)
		if err != nil {
			panic(fmt.Errorf("failed to get connection: %v", err))
		}
		dsn = *dbConnStr
	} else {
		postgresContainer := NewPgContainer(config, esc.ScriptPath)
		if err := postgresContainer.StartPostgresContainer(ctx); err != nil {
			log.Fatal(err.Error())
		}
		dsn = postgresContainer.DSN
		// Clean up the container
		defer func() {
			if err := postgresContainer.Terminate(ctx); err != nil {
				log.Fatalf("failed to terminate container: %s", err)
			}
		}()
	}
	db, err := goutils.ConnectToDb(
		dsn,
		goutils.OpenDatabaseConnection,
		0,
		1,
	)

	if err != nil {
		log.Fatalf("failed to connect to test database: %v", err)
	}
	esc.DB = db
	Setup(db)

	// Set up Echo instance
	e = echo.New()
	// Middleware
	validator := validator.New()

	validator.RegisterValidation("password", internal_middleware.ValidatePassword)
	e.Validator = &gum.DefaultValidator{Validator: validator}
	// e.Use(middleware.Logger())
	// e.Use(middleware.Recover())
	e.Use(gum.ErrorMiddleware)

	// Start repository
	userCredRepo := repository.NewUserCredentialsRepository(db)

	versionGroup := utils.CreateVersionedApiPath(e, "v1")

	// Start services
	authService := services.NewAuthService(userCredRepo, viper.GetViper())

	// Initialize your handlers
	handlers.
		NewAuthHandler(authService).
		RegisterAuthRoutes(versionGroup, internal_middleware.BearerAuthMiddleware)
	esc.Echo = e

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
	Cleanup(db)
	os.Exit(exitVal)
}

func Setup(db *gorm.DB, entities ...interface{}) error {
	modelsList := []interface{}{
		&models.UserCredentials{},
	}
	// Run migrations
	if err := db.AutoMigrate(modelsList...); err != nil {
		log.Fatalf("failed to migrate: %v", err)
	}
	// Create entities
	for _, entity := range entities {
		if err := db.Create(entity).Error; err != nil {
			return err
		}
	}

	return nil
}

func Cleanup(db *gorm.DB, targets ...interface{}) error {

	if targets != nil && len(targets) > 0 {
		if err := db.Migrator().DropTable(targets...); err != nil {
			log.Fatalf("failed to drop table " + err.Error())
		}
	} else {
		modelsList := []interface{}{
			&models.UserCredentials{},
		}
		if err := db.Migrator().DropTable(modelsList...); err != nil {
			log.Fatalf("failed to drop table " + err.Error())
		}
	}
	return nil
}
