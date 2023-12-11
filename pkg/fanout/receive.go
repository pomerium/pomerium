package fanout

import (
	"context"
	"fmt"
	"time"
)

// ReceiverCallback is the callback function that is called for each message received
// if an error is returned, Receive will return immediately with that error, closing the subscriber
type ReceiverCallback[T any] func(ctx context.Context, msg T) error

// ReceiveOption is an option for receiver
type ReceiveOption[T any] func(*subscriber[T])

// WithFilter returns a ReceiveOption that filters messages for the subscriber
// if the filter returns false, the message is not sent to the subscriber
// this function is called for each message received and subsequently for each subscriber
// and should not be computationally expensive or block
func WithFilter[T any](filter func(T) bool) ReceiveOption[T] {
	return func(sub *subscriber[T]) {
		sub.filter = filter
	}
}

// WithOnSubscriberAdded should only be used for tests
func WithOnSubscriberAdded[T any](onAdded func()) ReceiveOption[T] {
	return func(sub *subscriber[T]) {
		sub.onAdded = onAdded
	}
}

// Receive subscribes to receive messages until the context is canceled or an error occurs
// onMessage is called for each message received.
// if an error is returned, Receive will return immediately
func (f *FanOut[T]) Receive(ctx context.Context, onMessage ReceiverCallback[T], opts ...ReceiveOption[T]) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	messages := make(chan T, f.cfg.receiverBufferSize)
	sub := newSubscriber[T](messages, f.done, cancel, opts...)

	err := f.addSubscriber(ctx, sub)
	if err != nil {
		return fmt.Errorf("add subscriber: %w", err)
	}

	err = f.receiveLoop(ctx, messages, onMessage)
	if err != nil {
		return fmt.Errorf("receive: %w", err)
	}

	return nil
}

func newSubscriber[T any](
	messages chan<- T,
	done <-chan struct{},
	cancel context.CancelCauseFunc,
	opts ...ReceiveOption[T],
) *subscriber[T] {
	sub := &subscriber[T]{
		messages: messages,
		done:     done,
		cancel:   cancel,
	}
	for _, opt := range opts {
		opt(sub)
	}
	return sub
}

func (f *FanOut[T]) receiveLoop(
	ctx context.Context,
	messages <-chan T,
	onMessage ReceiverCallback[T],
) error {
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-f.done:
			return ErrStopped
		case msg, ok := <-messages:
			if !ok {
				return ErrSubscriberEvicted
			}
			err := callWithTimeout(ctx, f.cfg.receiverCallbackTimeout, onMessage, msg)
			if err != nil {
				return fmt.Errorf("onMessage callback: %w", err)
			}
		}
	}
}

func callWithTimeout[T any](
	ctx context.Context,
	timeout time.Duration,
	cb ReceiverCallback[T],
	msg T,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return cb(ctx, msg)
}
