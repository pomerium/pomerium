package testutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
)

func StartS3CompatContainer(tb testing.TB) (endpoint, accessKey, secretKey string) {
	tb.Helper()
	ctx := tb.Context()

	const (
		port           = "8333/tcp"
		accessKeyValue = "seaweedfsadmin"
		secretKeyValue = "seaweedfsadmin"
	)

	container := mustRunContainer(tb, "chrislusf/seaweedfs:4.46",
		testcontainers.WithLogger(log.TestLogger(tb)),
		testcontainers.WithExposedPorts(port),
		testcontainers.WithEnv(map[string]string{
			"AWS_ACCESS_KEY_ID":     accessKeyValue,
			"AWS_SECRET_ACCESS_KEY": secretKeyValue,
		}),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/readyz").
				WithPort(port).
				WithStartupTimeout(2*time.Minute),
		),
	)

	host, err := container.Host(ctx)
	require.NoError(tb, err, "failed to get SeaweedFS host")
	mappedPort, err := container.MappedPort(ctx, port)
	require.NoError(tb, err, "failed to get SeaweedFS S3 port")

	endpoint = host + ":" + mappedPort.Port()
	accessKey = accessKeyValue
	secretKey = secretKeyValue

	return endpoint, accessKey, secretKey
}
