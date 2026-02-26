package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

func StartMinio(tb testing.TB) (endpoint, accessKey, secretKey string) {
	tb.Helper()

	container := mustRunContainer(tb, "minio/minio:RELEASE.2024-01-16T16-07-38Z",
		testcontainers.WithLogger(log.TestLogger(tb)),
		testcontainers.WithExposedPorts("9000/tcp"),
		testcontainers.WithEnv(map[string]string{
			"MINIO_ROOT_USER":     "minioadmin",
			"MINIO_ROOT_PASSWORD": "minioadmin",
		}),
		testcontainers.WithCmd("server", "/data", "--console-address", ":9001"),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/minio/health/ready").WithPort("9000/tcp")),
	)

	ctx := oteltrace.ContextWithSpan(tb.Context(), trace.ValidNoopSpan{})
	host, err := container.Host(ctx)
	require.NoError(tb, err, "failed to get minio host")
	port, err := container.MappedPort(ctx, "9000")
	require.NoError(tb, err, "failed to get minio port")

	endpoint = host + ":" + port.Port()
	accessKey = "minioadmin"
	secretKey = "minioadmin"

	return endpoint, accessKey, secretKey
}
