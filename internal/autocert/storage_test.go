package autocert

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestGCSStorage(t *testing.T) {
	t.Skip("fakeserver doesn't support multipart uploads")

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	t.Cleanup(clearTimeout)

	require.NoError(t, testutil.WithTestGCS(t, "bucket", func() error {
		s, err := GetCertMagicStorage(ctx, "gs://bucket/some/prefix")
		if !assert.NoError(t, err) {
			return nil
		}

		runStorageTests(t, s)
		return nil
	}))
}

func TestS3Storage(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	t.Cleanup(clearTimeout)

	require.NoError(t, testutil.WithTestMinIO(t, "bucket", func(endpoint string) error {
		s, err := GetCertMagicStorage(ctx, "s3://"+endpoint+"/bucket/some/prefix")
		if !assert.NoError(t, err) {
			return nil
		}

		runStorageTests(t, s)
		return nil
	}))
}

func runStorageTests(t *testing.T, s certmagic.Storage) {
	t.Helper()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	t.Cleanup(clearTimeout)

	for _, key := range []string{"1", "a/1", "b/c/2"} {
		assert.NoError(t, s.Store(ctx, key, []byte{1, 2, 3}), "should store")
		assert.True(t, s.Exists(ctx, key), "should exist after storing")
		data, err := s.Load(ctx, key)
		if assert.NoError(t, err, "should load") {
			assert.Equal(t, []byte{1, 2, 3}, data)
		}
		ki, err := s.Stat(ctx, key)
		if assert.NoError(t, err) {
			assert.Equal(t, true, ki.IsTerminal)
		}
	}
	keys, err := s.List(ctx, "", true)
	assert.NoError(t, err, "should list recursively")
	assert.Equal(t, []string{"1", "a/1", "b/c/2"}, keys)
	keys, err = s.List(ctx, "b/", false)
	assert.NoError(t, err, "should list non-recursively")
	assert.Equal(t, []string{"b/c/"}, keys)

	assert.NoError(t, s.Delete(ctx, "a/b/c"), "should delete")
	_, err = s.Load(ctx, "a/b/c")
	assert.Error(t, err)

	assert.NoError(t, s.Lock(ctx, "a"), "should lock")

	time.AfterFunc(time.Second*2, func() {
		s.Unlock(ctx, "a")
	})

	assert.NoError(t, s.Lock(ctx, "a"), "should re-lock")
}
