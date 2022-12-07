package autocert

import (
	"context"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestStorage(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	t.Cleanup(clearTimeout)

	runTests := func(t *testing.T, s certmagic.Storage) {
		t.Helper()

		for _, key := range []string{"1", "a/1", "b/c/2"} {
			assert.NoError(t, s.Store(ctx, key, []byte{1, 2, 3}))
			assert.True(t, s.Exists(ctx, key))
			data, err := s.Load(ctx, key)
			if assert.NoError(t, err) {
				assert.Equal(t, []byte{1, 2, 3}, data)
			}
			ki, err := s.Stat(ctx, key)
			if assert.NoError(t, err) {
				assert.Equal(t, true, ki.IsTerminal)
			}
		}
		keys, err := s.List(ctx, "", true)
		assert.NoError(t, err)
		assert.Equal(t, []string{"1", "a/1", "b/c/2"}, keys)
		keys, err = s.List(ctx, "b/", false)
		assert.NoError(t, err)
		assert.Equal(t, []string{"b/c/"}, keys)

		assert.NoError(t, s.Delete(ctx, "a/b/c"))
		_, err = s.Load(ctx, "a/b/c")
		assert.Error(t, err)

		assert.NoError(t, s.Lock(ctx, "a"))

		time.AfterFunc(time.Second*2, func() {
			s.Unlock(ctx, "a")
		})

		assert.NoError(t, s.Lock(ctx, "a"))
	}

	t.Run("s3", func(t *testing.T) {
		require.NoError(t, testutil.WithTestMinIO(t, "bucket", func(endpoint string) error {
			s, err := GetCertMagicStorage(ctx, "s3://"+endpoint+"/bucket/some/prefix")
			if !assert.NoError(t, err) {
				return nil
			}

			runTests(t, s)
			return nil
		}))
	})
}
