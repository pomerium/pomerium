package testutil

import (
	"fmt"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// WithTestMinIO starts a test MinIO server
func WithTestMinIO(t *testing.T, bucket string, handler func(endpoint string)) {
	t.Helper()

	ctx := GetContext(t, maxWait)
	ctx = oteltrace.ContextWithSpan(ctx, trace.ValidNoopSpan{})

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Name:         "pomerium-minio",
			Image:        "quay.io/minio/minio:RELEASE.2022-12-02T19-19-22Z",
			ExposedPorts: []string{"9000/tcp"},
			WaitingFor: wait.ForAll(
				wait.ForListeningPort("9000"),
			),
			Env: map[string]string{
				"MINIO_ROOT_USER":     "pomeriumtest",
				"MINIO_ROOT_PASSWORD": "pomeriumtest",
			},
			Cmd: []string{"server", "/data"},
		},
		Started: true,
		Logger:  log.TestLogger(t),
	})
	if err != nil {
		t.Fatalf("testutil/minio: failed to create container: %v", err)
	}

	port, err := container.MappedPort(ctx, "9000")
	if err != nil {
		t.Fatalf("testutil/minio: failed to get mapped port: %v", err)
	}

	endpoint := fmt.Sprintf("localhost:%s", port.Port())
	client, err := minio.New(endpoint, &minio.Options{
		Creds: credentials.NewStaticV4("pomeriumtest", "pomeriumtest", ""),
	})
	if err != nil {
		t.Fatalf("testutil/minio: failed to create minio client: %v", err)
	}

	err = client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		t.Fatalf("testutil/minio: failed to create minio bucket: %v", err)
	}

	t.Setenv("MINIO_ROOT_USER", "pomeriumtest")
	t.Setenv("MINIO_ROOT_PASSWORD", "pomeriumtest")
	t.Setenv("AWS_ACCESS_KEY_ID", "pomeriumtest")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "pomeriumtest")

	handler(endpoint)
}
