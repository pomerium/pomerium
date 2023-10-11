package reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/zero/reconciler"
)

func TestRestart(t *testing.T) {
	t.Parallel()

	for i := 0; i < 20; i++ {
		t.Run(fmt.Sprintf("quit on error %d", i), func(t *testing.T) {
			t.Parallel()

			errExpected := errors.New("execFn error")
			count := 0
			err := reconciler.RunWithRestart(context.Background(),
				func(context.Context) error {
					count++
					if count == 1 {
						return errExpected
					}
					return errors.New("execFn should not be called more than once")
				},
				func(ctx context.Context) error {
					<-ctx.Done()
					return ctx.Err()
				},
			)
			assert.ErrorIs(t, err, errExpected)
		})

		t.Run(fmt.Sprintf("quit on no error %d", i), func(t *testing.T) {
			t.Parallel()

			count := 0
			err := reconciler.RunWithRestart(context.Background(),
				func(context.Context) error {
					count++
					if count == 1 {
						return nil
					}
					return errors.New("execFn should not be called more than once")
				},
				func(ctx context.Context) error {
					<-ctx.Done()
					return ctx.Err()
				},
			)
			assert.NoError(t, err)
		})

		t.Run(fmt.Sprintf("parent context canceled %d", i), func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			ready := make(chan struct{})
			err := reconciler.RunWithRestart(ctx,
				func(context.Context) error {
					<-ready
					cancel()
					return ctx.Err()
				},
				func(context.Context) error {
					close(ready)
					<-ctx.Done()
					return ctx.Err()
				},
			)
			assert.ErrorIs(t, err, context.Canceled)
		})

		t.Run(fmt.Sprintf("triggers restart %d", i), func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			errExpected := errors.New("execFn error")
			count := 0
			ready := make(chan struct{})
			err := reconciler.RunWithRestart(ctx,
				func(ctx context.Context) error {
					count++
					if count == 1 { // wait for us to be restarted
						close(ready)
						<-ctx.Done()
						return ctx.Err()
					} else if count == 2 { // just quit
						return errExpected
					}
					return errors.New("execFn should not be called more than twice")
				},
				func(ctx context.Context) error {
					<-ready
					return errors.New("restart required")
				},
			)
			assert.ErrorIs(t, err, errExpected)
		})
	}
}
