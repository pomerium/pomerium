package fanout_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/pkg/fanout"
)

func TestFanOutStopped(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	f := fanout.Start[int](ctx, fanout.WithPublishTimeout(time.Millisecond*10))
	assert.Eventually(t, func() bool {
		return errors.Is(f.Publish(t.Context(), 1), fanout.ErrStopped)
	}, 5*time.Second, 10*time.Millisecond)

	err := f.Receive(t.Context(), func(_ context.Context, _ int) error {
		return nil
	})
	assert.ErrorIs(t, err, fanout.ErrStopped)
}

func TestFanOutEvictSlowSubscriber(t *testing.T) {
	t.Parallel()

	timeout := time.Second * 5
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)

	f := fanout.Start[int](ctx,
		fanout.WithReceiverBufferSize(1),
		fanout.WithReceiverCallbackTimeout(timeout),
	)

	subscriberAdded := make(chan struct{})

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		err := f.Receive(ctx, func(ctx context.Context, _ int) error {
			select {
			case <-ctx.Done():
				// context was canceled as expected
				// when the subscriber was evicted
			case <-time.After(timeout / 2):
				t.Error("receiver context was not canceled")
			}
			return nil
		}, fanout.WithOnSubscriberAdded[int](func() {
			close(subscriberAdded)
		}))
		assert.ErrorIs(t, err, fanout.ErrSubscriberEvicted, "expect explicit error indicating subscriber eviction")
		return nil
	})
	eg.Go(func() error {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for subscriber: %w", ctx.Err())
		case <-subscriberAdded:
		}
		// this message will be consumed by the subscriber above, which will block in the callback
		assert.NoError(t, f.Publish(ctx, 1))
		// this message will get into fanout-receiver's buffer as the subscriber is blocked
		assert.NoError(t, f.Publish(ctx, 1))
		// this messsage will cause the subscriber to be evicted as all buffers are full
		assert.NoError(t, f.Publish(ctx, 1))
		return nil
	})
	require.NoError(t, eg.Wait())
}

func TestFanOutReceiverCancelOnError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	f := fanout.Start[int](ctx)
	receiverErr := errors.New("receiver error")
	errch := make(chan error, 1)

	ready := make(chan struct{})
	go func() {
		errch <- f.Receive(ctx, func(_ context.Context, _ int) error {
			return receiverErr
		}, fanout.WithOnSubscriberAdded[int](func() { close(ready) }))
	}()

	<-ready
	require.NoError(t, f.Publish(ctx, 1))
	assert.ErrorIs(t, <-errch, receiverErr)
}

func TestFanOutFilter(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
	t.Cleanup(cancel)

	f := fanout.Start[int](ctx)
	ready := make(chan struct{})
	results := make(chan int)
	go func() {
		_ = f.Receive(ctx, func(_ context.Context, msg int) error {
			results <- msg
			return nil
		},
			fanout.WithFilter(func(msg int) bool { return msg%2 == 0 }),
			fanout.WithOnSubscriberAdded[int](func() { close(ready) }),
		)
	}()
	<-ready
	t.Log("ready to publish")
	for i := 0; i < 10; i++ {
		assert.NoError(t, f.Publish(ctx, i))
	}
	t.Log("published all messages")

	for i := 0; i < 9; i += 2 {
		assert.Equal(t, i, <-results)
	}
}

func BenchmarkFanout(b *testing.B) {
	ctx, cancel := context.WithTimeout(b.Context(), time.Minute*10)
	b.Cleanup(cancel)

	cycles := 1

	f := fanout.Start[int](ctx)
	errStopReceiver := errors.New("stop receiver")
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(-1)
	ready := make(chan struct{}, b.N)
	for i := 0; i < b.N; i++ {
		want := i
		eg.Go(func() error {
			seen := 0
			err := f.Receive(ctx, func(_ context.Context, _ int) error {
				if seen++; seen == cycles {
					return errStopReceiver
				}
				return nil
			},
				fanout.WithOnSubscriberAdded[int](func() { ready <- struct{}{} }),
				fanout.WithFilter(func(msg int) bool { return msg == want }),
			)
			if !errors.Is(err, errStopReceiver) && !errors.Is(err, context.Canceled) {
				b.Error(err)
				return err
			}
			return nil
		})
	}
	eg.Go(func() error {
		for i := 0; i < b.N; i++ {
			<-ready
		}

		for c := 0; c < cycles; c++ {
			for i := 0; i < b.N; i++ {
				err := f.Publish(ctx, i)
				if err != nil {
					b.Error(err)
					return err
				}
			}
		}
		return nil
	})
	require.NoError(b, eg.Wait())
}
