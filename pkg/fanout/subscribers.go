package fanout

import (
	"context"
)

// subscriber represents an individual subscriber to a fanout
type subscriber[T any] struct {
	// messages is the channel that the subscriber receives messages on
	messages chan<- T
	// done is closed when the subscriber is closed
	// it is used to signal the dispatchLoop that the subscriber is closed and should be removed
	done <-chan struct{}
	// cancel is passed so that dispatchLoop can cancel the subscriber if it discards it from its side
	cancel context.CancelCauseFunc
	// filter identifies the messages that the subscriber is interested in.
	filter func(T) bool
	// onAdded is called when the subscriber is added to the fanout
	// it is only used for tests
	onAdded func()
}

// subscriberCloseFn is a function that closes a subscriber and propagates an error to it
type subscriberCloseFn func(err error)

// subscribers is a map of subscribers to their close functions
type subscribers[T any] map[*subscriber[T]]subscriberCloseFn

// closeAll closes all subscribers and propagates the given error to them
func (s subscribers[T]) closeAll(err error) {
	for _, close := range s {
		close(err)
	}
}

// add adds subscriber to the fanout
func (s subscribers[T]) add(sub *subscriber[T]) {
	s[sub] = func(err error) {
		close(sub.messages)
		sub.cancel(err)
		delete(s, sub)
	}
	if sub.onAdded != nil {
		sub.onAdded()
	}
}

// dispatch dispatches the given message to all subscribers
func (s subscribers[T]) dispatch(ctx context.Context, msg T) {
	for sub, close := range s {
		if sub.filter != nil && !sub.filter(msg) {
			continue
		}

		select {
		case <-ctx.Done():
			return
		case sub.messages <- msg:
		case <-sub.done:
			close(ErrSubscriberClosed)
		default:
			close(ErrSubscriberEvicted)
		}
	}
}
