// Package fanout implements a fan-out pattern that allows publishing messages to multiple subscribers
package fanout

import (
	"context"
	"errors"
)

var (
	// ErrSubscriberClosed is returned when a subscriber is closed on the subscriber side (Receive)
	ErrSubscriberClosed = errors.New("subscriber closed")
	// ErrSubscriberEvicted is returned when a subscriber is unable to keep up with the messages
	ErrSubscriberEvicted = errors.New("subscriber evicted, cannot keep up consuming messages")
	// ErrStopped is returned when the fanout is stopped
	ErrStopped = errors.New("fanout is stopped, no more messages will be accepted")
)

// FanOut is a fan-out pattern implementation that allows publishing messages to multiple subscribers
type FanOut[T any] struct {
	cfg         config
	done        <-chan struct{}
	messages    chan T
	subscribers chan *subscriber[T]
}

// Start creates and runs a new FanOut
func Start[T any](ctx context.Context, opts ...Option) *FanOut[T] {
	cfg := defaultFanOutConfig()
	cfg.apply(opts...)

	f := &FanOut[T]{
		cfg:         cfg,
		done:        ctx.Done(),
		messages:    make(chan T, cfg.publishBufferSize),
		subscribers: make(chan *subscriber[T], cfg.subscriberBufferSize),
	}
	go f.dispatchLoop(ctx)
	return f
}

func (f *FanOut[T]) dispatchLoop(ctx context.Context) {
	subscribers := make(subscribers[T])
	defer subscribers.closeAll(ErrStopped)

	for {
		select {
		case <-ctx.Done():
			return
		case sub := <-f.subscribers:
			subscribers.add(sub)
			continue
		case msg := <-f.messages:
			subscribers.dispatch(ctx, msg)
		}
	}
}

func (f *FanOut[T]) addSubscriber(ctx context.Context, sub *subscriber[T]) error {
	ctx, cancel := context.WithTimeout(ctx, f.cfg.addSubscriberTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-f.done:
		return ErrStopped
	case f.subscribers <- sub:
		return nil
	}
}
