package testhelpers

import (
	"context"
	"log"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/viper"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type PgContainer struct {
	*postgres.PostgresContainer
	DSN        string
	dbName     string
	dbUser     string
	dbPassword string
	scriptPath string
}

func NewPgContainer(config *viper.Viper, scriptPath string) *PgContainer {
	// Get the directory of the current file (testhelpers.go)
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to get runtime caller information")
	}
	dir := filepath.Dir(filename)
	// path, _ := filepath.Rel("../"+dir, "db/init-e2e.sql")
	// Construct the relative path to init-e2e.sql
	dbName := config.GetString("DATABASE_DBNAME")
	dbUser := config.GetString("DATABASE_USER")
	dbPassword := config.GetString("DATABASE_PASSWORD")
	return &PgContainer{
		dbName:     dbName,
		dbUser:     dbUser,
		dbPassword: dbPassword,
		scriptPath: dir + "/../db/init-e2e.sql",
	}
}

func (pgc *PgContainer) StartPostgresContainer(
	ctx context.Context,
) error {
	// cwd, err := os.Getwd()
	// if err != nil {
	// 	return err
	// }
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("docker.io/postgres:16-alpine"),
		postgres.WithInitScripts(pgc.scriptPath),
		// postgres.WithConfigFile(filepath.Join("testdata", "my-postgres.conf")),
		postgres.WithDatabase(pgc.dbName),
		postgres.WithUsername(pgc.dbUser),
		postgres.WithPassword(pgc.dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	if err != nil {
		log.Fatalf("failed to start container: %s", err)
		return err
	}

	dsn, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to start container: %s", err)
		return err
	}
	pgc.DSN = dsn
	pgc.PostgresContainer = postgresContainer

	return nil
}
