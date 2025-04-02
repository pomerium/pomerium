// Package testutil contains helper functions for tests.
package testutil

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// WithTestPostgres starts a postgres database.
func WithTestPostgres(t *testing.T, handler func(dsn string)) {
	t.Helper()

	ctx := GetContext(t, maxWait)
	ctx = oteltrace.ContextWithSpan(ctx, trace.ValidNoopSpan{})

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Name:         "pomerium-postgres",
			Image:        "postgres:16",
			ExposedPorts: []string{"5432/tcp"},
			WaitingFor: wait.ForAll(
				wait.ForLog("database system is ready to accept connections"),
				wait.ForListeningPort("5432"),
			),
			Env: map[string]string{
				"POSTGRES_DB":       "pomeriumtest",
				"POSTGRES_PASSWORD": "pomeriumtest",
				"POSTGRES_USER":     "pomeriumtest",
			},
			Cmd: []string{"-c", "max_connections=1000"},
		},
		Started: true,
		Logger:  testcontainers.TestLogger(t),
		Reuse:   true,
	})
	if err != nil {
		t.Fatalf("testutil/postgres: failed to create container: %v", err)
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("testutil/postgres: failed to get mapped port: %v", err)
	}

	// create the next database
	id := uuid.New()
	dbName := fmt.Sprintf("pomeriumtest%s", hex.EncodeToString(id[:]))
	t.Logf("postgres: creating %s", dbName)

	// run the test against the new database
	db, err := pgx.Connect(ctx, fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@localhost:%s/pomeriumtest?sslmode=disable", port.Port()))
	if err != nil {
		t.Fatalf("testutil/postgres: failed to connect to postgres: %v", err)
	}

	_, err = db.Exec(ctx, `CREATE DATABASE `+dbName)
	if err != nil {
		t.Fatalf("testutil/postgres: failed to create database: %v", err)
	}

	err = db.Close(ctx)
	if err != nil {
		t.Fatalf("testutil/postgres: failed to close database: %v", err)
	}

	handler(fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@localhost:%s/%s?sslmode=disable", port.Port(), dbName))
}
