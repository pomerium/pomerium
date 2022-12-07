package testutil

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// WithTestMinIO starts a test MinIO server
func WithTestMinIO(t *testing.T, bucket string, handler func(endpoint string) error) error {
	t.Helper()

	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		return err
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "quay.io/minio/minio",
		Tag:        "RELEASE.2022-12-02T19-19-22Z",
		Env:        []string{"MINIO_ROOT_USER=pomerium", "MINIO_ROOT_PASSWORD=pomerium"},
		Cmd:        []string{"server", "/data"},
	})
	if err != nil {
		return err
	}
	_ = resource.Expire(uint(maxWait.Seconds()))
	go tailLogs(ctx, t, pool, resource)

	endpoint := fmt.Sprintf("localhost:%s", resource.GetPort("9000/tcp"))
	if err := pool.Retry(func() error {
		client, err := minio.New(endpoint, &minio.Options{
			Creds: credentials.NewStaticV4("pomerium", "pomerium", ""),
		})
		if err != nil {
			t.Logf("minio: %s", err)
			return err
		}

		err = client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
		if err != nil {
			t.Logf("minio: %s", err)
			return err
		}

		return nil
	}); err != nil {
		_ = pool.Purge(resource)
		return err
	}

	t.Setenv("MINIO_ROOT_USER", "pomerium")
	t.Setenv("MINIO_ROOT_PASSWORD", "pomerium")
	t.Setenv("AWS_ACCESS_KEY_ID", "pomerium")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "pomerium")
	e := handler(endpoint)

	if err := pool.Purge(resource); err != nil {
		return err
	}

	return e
}

func tailLogs(ctx context.Context, t *testing.T, pool *dockertest.Pool, resource *dockertest.Resource) {
	t.Helper()

	pr, pw := io.Pipe()
	go func() {
		s := bufio.NewScanner(pr)
		for s.Scan() {
			t.Logf("%s: %s", resource.Container.Config.Image, s.Text())
		}
	}()
	defer pw.Close()

	opts := docker.LogsOptions{
		Context: ctx,

		Stderr:      true,
		Stdout:      true,
		Follow:      true,
		Timestamps:  true,
		RawTerminal: true,

		Container: resource.Container.ID,

		OutputStream: pw,
	}

	_ = pool.Client.Logs(opts)
}
