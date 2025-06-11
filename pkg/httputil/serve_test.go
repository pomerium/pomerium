package httputil_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/pkg/httputil"
)

func TestServeWithGracefulStop(t *testing.T) {
	t.Parallel()

	t.Run("immediate", func(t *testing.T) {
		t.Parallel()

		li, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		h := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		})

		now := time.Now()
		err = httputil.ServeWithGracefulStop(ctx, h, li, time.Millisecond*100)
		elapsed := time.Since(now)
		assert.Nil(t, err)
		assert.Less(t, elapsed, time.Millisecond*100, "should complete immediately")
	})
	t.Run("graceful", func(t *testing.T) {
		t.Parallel()

		li, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)

		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				w.WriteHeader(http.StatusNoContent)
			case "/wait":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("\n"))
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-make(chan struct{}):
				}
			default:
				http.NotFound(w, r)
			}
		})

		now := time.Now()
		ctx, cancel := context.WithCancel(t.Context())
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			return httputil.ServeWithGracefulStop(ctx, h, li, time.Millisecond*100)
		})
		eg.Go(func() error {
			// poll until the server is ready
			for {
				res, err := http.Get("http://" + li.Addr().String() + "/")
				if err != nil {
					continue
				}
				res.Body.Close()

				break
			}

			// issue a stream request that will last indefinitely
			res, err := http.Get("http://" + li.Addr().String() + "/wait")
			if err != nil {
				return err
			}

			cancel()

			// wait until the request completes (should stop after the graceful timeout)
			io.ReadAll(res.Body)
			res.Body.Close()

			return nil
		})
		eg.Wait()
		elapsed := time.Since(now)
		assert.Greater(t, elapsed, time.Millisecond*100, "should complete after 100ms")
	})
}
