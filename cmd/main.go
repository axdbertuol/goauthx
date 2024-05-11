package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/axdbertuol/goauthx/internal/services"
	kc "github.com/axdbertuol/goauthx/internal/services/kafka_consumer"
	"github.com/axdbertuol/goauthx/internal/utils"
	goutils "github.com/axdbertuol/goutils/functions"
	gum "github.com/axdbertuol/goutils/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
	echoSwagger "github.com/swaggo/echo-swagger"

	_ "github.com/axdbertuol/goauthx/docs"
	"github.com/axdbertuol/goauthx/internal/handlers"
	internal_middleware "github.com/axdbertuol/goauthx/internal/middleware"
	"github.com/axdbertuol/goauthx/internal/models"
	"github.com/axdbertuol/goauthx/internal/repository"
)

// @title Swagger Example API
// @version 1.0
// @description This is a sample server Petstore server.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host petstore.swagger.io
// @BasePath /v1
func main() {
	// Load .env file
	var (
		defaultRetryDelay = 5 * time.Second
		defaultMaxRetries = 3
		env               string
	)
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file:", err)
	}

	// Initialize Viper
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	env = viper.GetString("ENVIRONMENT")

	// Initialize Echo instance
	e := echo.New()
	e.Debug = true

	// Middleware
	validator := validator.New()

	validator.RegisterValidation("password", internal_middleware.ValidatePassword)
	e.Validator = &gum.DefaultValidator{Validator: validator}

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(gum.ErrorMiddleware)
	if env == "local" {
		viper.Set("DATABASE_HOST", "localhost")
		viper.Set("DATABASE_PORT", "5433")
		viper.Set("DATABASE_USERNAME", "postgres")
		viper.Set("DATABASE_PASSWORD", "postgres")
		// viper.Set("DATABASE_DBNAME", "testdb")
		viper.Set("KAFKA_BROKER_URL", "localhost:9092")
	}

	dbConnStr, err := goutils.GetConnection(viper.GetViper())
	if err != nil {
		panic(fmt.Errorf("failed to get connection: %v", err))
	}

	db, err := goutils.ConnectToDb(
		*dbConnStr,
		goutils.OpenDatabaseConnection,
		defaultRetryDelay,
		defaultMaxRetries,
	)
	if err != nil {
		panic(err)
	}
	if env != "production" {
		modelsList := []interface{}{
			&models.UserCredentials{},
		}
		if err := db.Migrator().DropTable(modelsList...); err != nil {
			panic("failed to drop table " + err.Error())
		}
		if err := db.AutoMigrate(modelsList...); err != nil {
			panic("failed to create tables" + err.Error())
		}
	}
	logger := slog.New(
		slog.NewJSONHandler(
			os.Stdout,
			&slog.HandlerOptions{Level: slog.LevelError},
		),
	)

	// Start repository
	userCredRepo := repository.NewUserCredentialsRepository(db)

	versionGroup := utils.CreateVersionedApiPath(e, "v1")

	// Start services
	authService := services.NewAuthService(userCredRepo, viper.GetViper())

	// Initialize your handlers
	handlers.
		NewAuthHandler(authService).
		RegisterAuthRoutes(versionGroup, internal_middleware.BearerAuthMiddleware)
	aeh := handlers.NewAuthEventHandler(authService, logger)

	e.GET("/swagger/*", echoSwagger.WrapHandler)
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	// Start kafka consumer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		quitCh = make(chan struct{}, 1)
		errCh  = make(chan error, 10)
	)
	args := kc.KafkaConsumerArgs{
		Ctx:             ctx,
		SignalCh:        quitCh,
		ErrCh:           errCh,
		SwitchEventFunc: aeh.SwitchEvents,
	}

	go kc.Start(args)
	go func() {
		for err := range errCh {
			log.Println("Kafka consumer error:", err)
		}
	}()
	port := viper.GetString("APP_PORT")

	// Start server
	log.Println("Server started at :" + port)
	e.Logger.Fatal(e.Start(":" + port))
}
