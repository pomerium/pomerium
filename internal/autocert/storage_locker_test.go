package autocert_test

import (
	"context"
	"io/fs"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/autocert"
)

func TestLocker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		kvs := map[string][]byte{}
		l := autocert.NewLocker(
			func(_ context.Context, key string, value []byte) error {
				mu.Lock()
				kvs[key] = value
				mu.Unlock()
				return nil
			},
			func(_ context.Context, key string) ([]byte, error) {
				mu.Lock()
				value, ok := kvs[key]
				mu.Unlock()
				if !ok {
					return nil, fs.ErrNotExist
				}
				return value, nil
			},
			func(_ context.Context, key string) error {
				mu.Lock()
				delete(kvs, key)
				mu.Unlock()
				return nil
			},
		)

		assert.NoError(t, l.Lock(t.Context(), "a"))

		lockErrCh := make(chan error, 1)
		go func() {
			time.Sleep(time.Second * 30)
			assert.NoError(t, l.Unlock(t.Context(), "a"))
		}()
		go func() {
			lockErrCh <- l.Lock(t.Context(), "a")
		}()
		synctest.Wait()

		assert.NoError(t, <-lockErrCh)
	})
}
