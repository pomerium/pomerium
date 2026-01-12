package autocert

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestS3Storage(t *testing.T) {
	t.Parallel()
	bucket := uuid.NewString()
	testutil.WithTestS3(t, func(endpoint string) {
		s, err := GetCertMagicStorage(t.Context(), "s3://"+endpoint+"/"+bucket+"/some/prefix")
		require.NoError(t, err)
		runStorageTests(t, s)
	})
}

func runStorageTests(t *testing.T, s Storage) {
	t.Helper()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*30)
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

	ok, err := s.TryLock(ctx, "b")
	assert.True(t, ok, "should lock")
	assert.NoError(t, err)

	ok, err = s.TryLock(ctx, "b")
	assert.False(t, ok, "should not lock")
	assert.NoError(t, err)

	err = s.Unlock(ctx, "b")
	assert.NoError(t, err)

	err = s.Lock(ctx, "b")
	assert.NoError(t, err, "should re-lock")
}
