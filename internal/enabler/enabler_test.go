package enabler_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/enabler"
)

func TestEnabler(t *testing.T) {
	t.Parallel()

	t.Run("enabled immediately", func(t *testing.T) {
		t.Parallel()

		e := enabler.New("test", enabler.HandlerFunc(func(_ context.Context) error {
			return errors.New("ERROR")
		}), true)
		err := e.Run(t.Context())
		assert.Error(t, err)
	})
	t.Run("enabled delayed", func(t *testing.T) {
		t.Parallel()

		e := enabler.New("test", enabler.HandlerFunc(func(_ context.Context) error {
			return errors.New("ERROR")
		}), false)
		time.AfterFunc(time.Millisecond*10, e.Enable)
		err := e.Run(t.Context())
		assert.Error(t, err)
	})
	t.Run("disabled", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		var started, stopped atomic.Int64
		e := enabler.New("test", enabler.HandlerFunc(func(ctx context.Context) error {
			started.Add(1)
			<-ctx.Done()
			stopped.Add(1)
			return context.Cause(ctx)
		}), true)
		time.AfterFunc(time.Millisecond*10, e.Disable)
		go e.Run(ctx)

		assert.Eventually(t, func() bool { return stopped.Load() == 1 }, time.Second, time.Millisecond*100,
			"should stop RunEnabled")

		e.Enable()

		assert.Eventually(t, func() bool { return started.Load() == 2 }, time.Second, time.Millisecond*100,
			"should re-start RunEnabled")
	})
}
