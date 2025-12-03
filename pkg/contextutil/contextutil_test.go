package contextutil_test

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/contextutil"
)

func TestMerge(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			err := errors.New("test error")

			ctx, cancel := contextutil.Merge()
			cancel(err)

			deadline, ok := ctx.Deadline()
			assert.Zero(t, deadline)
			assert.False(t, ok)

			synctest.Wait()

			select {
			case <-ctx.Done():
				assert.ErrorIs(t, context.Cause(ctx), err)
			default:
				assert.Fail(t, "should cancel merged context")
			}
		})
	})
	t.Run("value", func(t *testing.T) {
		t.Parallel()

		type contextKey string
		k1 := contextKey("key1")
		k2 := contextKey("key2")
		k3 := contextKey("key3")

		ctx1 := context.WithValue(context.WithValue(t.Context(), k1, "value1"), k3, "value1")
		ctx2 := context.WithValue(context.WithValue(t.Context(), k2, "value2"), k3, "value2")
		ctx3, _ := contextutil.Merge(ctx1, ctx2)
		ctx3 = context.WithValue(ctx3, k3, "value3")
		assert.Equal(t, "value1", ctx3.Value(k1))
		assert.Equal(t, "value2", ctx3.Value(k2))
		assert.Equal(t, "value3", ctx3.Value(k3))
	})
	t.Run("cancel", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			err := errors.New("test error")

			ctx1, cancel1 := context.WithCancel(t.Context())
			defer cancel1()
			ctx2, cancel2 := context.WithCancelCause(t.Context())
			ctx3, _ := contextutil.Merge(ctx1, ctx2)
			cancel2(err)

			synctest.Wait()

			select {
			case <-ctx3.Done():
				assert.ErrorIs(t, context.Cause(ctx3), err)
			default:
				assert.Fail(t, "should cancel merged context")
			}
		})
	})
	t.Run("deadline", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			err1 := errors.New("test error 1")
			err2 := errors.New("test error 2")

			ctx1, cancel1 := context.WithTimeoutCause(t.Context(), 2*time.Minute, err1)
			defer cancel1()
			ctx2, cancel2 := context.WithTimeoutCause(t.Context(), 4*time.Minute, err2)
			defer cancel2()
			ctx3, cancel3 := contextutil.Merge(ctx1, ctx2)
			defer cancel3(context.Canceled)

			deadline, ok := ctx3.Deadline()
			assert.NotZero(t, deadline)
			assert.True(t, ok)

			time.Sleep(2 * time.Minute)
			synctest.Wait()

			select {
			case <-ctx3.Done():
				assert.ErrorIs(t, context.Cause(ctx3), err1)
			default:
				assert.Fail(t, "should use deadline")
			}
		})
	})
}
