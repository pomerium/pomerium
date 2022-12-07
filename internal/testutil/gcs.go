package testutil

import (
	"context"
	"fmt"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/ory/dockertest/v3"
)

// WithTestGCS starts a GCS storage emulator.
func WithTestGCS(t *testing.T, bucket string, handler func() error) error {
	t.Helper()

	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		return err
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "fsouza/fake-gcs-server",
		Tag:        "1.42.2",
		Cmd:        []string{"-scheme", "http"},
	})
	if err != nil {
		return err
	}
	_ = resource.Expire(uint(maxWait.Seconds()))
	go tailLogs(ctx, t, pool, resource)

	t.Setenv("STORAGE_EMULATOR_HOST", fmt.Sprintf("localhost:%s", resource.GetPort("4443/tcp")))
	if err := pool.Retry(func() error {
		client, err := storage.NewClient(ctx)
		if err != nil {
			t.Logf("gcs: %s", err)
			return err
		}

		err = client.Bucket(bucket).Create(ctx, "", nil)
		if err != nil {
			t.Logf("gcs: %s", err)
			return err
		}

		return nil
	}); err != nil {
		_ = pool.Purge(resource)
		return err
	}

	e := handler()

	if err := pool.Purge(resource); err != nil {
		return err
	}

	return e
}
