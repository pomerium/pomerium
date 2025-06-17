package retry_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/retry"
)

func TestRetry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	limit := retry.WithMaxInterval(time.Second * 5)

	t.Run("no error", func(t *testing.T) {
		t.Parallel()

		err := retry.Retry(ctx, "test", func(_ context.Context) error {
			return nil
		}, limit)
		require.NoError(t, err)
	})

	t.Run("eventually succeeds", func(t *testing.T) {
		t.Parallel()
		i := 0
		err := retry.Retry(ctx, "test", func(_ context.Context) error {
			if i++; i > 2 {
				return nil
			}
			return fmt.Errorf("transient %d", i)
		}, limit)
		require.NoError(t, err)
	})

	t.Run("eventually fails", func(t *testing.T) {
		t.Parallel()
		i := 0
		err := retry.Retry(ctx, "test", func(_ context.Context) error {
			if i++; i > 2 {
				return retry.NewTerminalError(errors.New("the end"))
			}
			return fmt.Errorf("transient %d", i)
		})
		require.Error(t, err)
	})

	t.Run("context canceled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		err := retry.Retry(ctx, "test", func(_ context.Context) error {
			return fmt.Errorf("retry")
		})
		require.Error(t, err)
	})

	t.Run("context canceled after retry", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		err := retry.Retry(ctx, "test", func(_ context.Context) error {
			cancel()
			return fmt.Errorf("retry")
		})
		require.Error(t, err)
	})

	t.Run("success after watch hook", func(t *testing.T) {
		t.Parallel()
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		ok := false
		err := retry.Retry(ctx, "test", func(_ context.Context) error {
			if ok {
				return nil
			}
			return fmt.Errorf("retry")
		}, retry.WithWatch("watch", ch, func(_ context.Context) error {
			ok = true
			return nil
		}), limit)
		require.NoError(t, err)
	})

	t.Run("success after watch hook retried", func(t *testing.T) {
		t.Parallel()
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		ok := false
		i := 0
		err := retry.Retry(ctx, "test", func(_ context.Context) error {
			if ok {
				return nil
			}
			return fmt.Errorf("retry test")
		}, retry.WithWatch("watch", ch, func(_ context.Context) error {
			if i++; i > 1 {
				ok = true
				return nil
			}
			return fmt.Errorf("retry watch")
		}), limit)
		require.NoError(t, err)
	})

	t.Run("watch hook fails", func(t *testing.T) {
		t.Parallel()
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		err := retry.Retry(ctx, "test", func(_ context.Context) error {
			return fmt.Errorf("retry")
		}, retry.WithWatch("watch", ch, func(_ context.Context) error {
			return retry.NewTerminalError(fmt.Errorf("watch"))
		}), limit)
		require.Error(t, err)
	})
}
