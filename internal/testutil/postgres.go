// Package testutil contains helper functions for tests.
package testutil

import (
	"fmt"
	"testing"

	"github.com/docker/go-connections/nat"
	_ "github.com/jackc/pgx/v5/stdlib" // for pgx sql driver
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

func StartPostgres(tb testing.TB) (dsn string) {
	tb.Helper()

	container := mustRunContainer(tb, "postgres:16",
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_DB":       "pomeriumtest",
			"POSTGRES_PASSWORD": "pomeriumtest",
			"POSTGRES_USER":     "pomeriumtest",
		}),
		testcontainers.WithCmd("-c", "max_connections=1000"),
		testcontainers.WithWaitStrategy(wait.ForSQL("5432/tcp", "pgx", func(host string, port nat.Port) string {
			return fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@%s:%s/pomeriumtest?sslmode=disable", host, port.Port())
		})),
	)

	ctx := oteltrace.ContextWithSpan(tb.Context(), trace.ValidNoopSpan{})
	host, err := container.Host(ctx)
	require.NoError(tb, err, "failed to get postgres host")
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(tb, err, "failed to get postgres port")

	return fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@%s:%s/pomeriumtest?sslmode=disable", host, port.Port())
}
