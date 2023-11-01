package events

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

type (
	// A Listener is a function that listens for events of type T.
	Listener[T any] func(T)
	// A Handle represents a listener.
	Handle string

	addListenerEvent[T any] struct {
		listener Listener[T]
		handle   Handle
	}
	removeListenerEvent[T any] struct {
		handle Handle
	}
	dispatchEvent[T any] struct {
		event T
	}
)

// A Target is a target for events.
//
// Listeners are added with AddListener with a function to be called when the event occurs.
// AddListener returns a Handle which can be used to remove a listener with RemoveListener.
//
// Dispatch dispatches events to all the registered listeners.
//
// Target is safe to use in its zero state.
//
// The first time any method of Target is called a background goroutine is started that handles
// any requests and maintains the state of the listeners. Each listener also starts a
// separate goroutine so that all listeners can be invoked concurrently.
//
// The channels to the main goroutine and to the listener goroutines have a size of 1 so typically
// methods and dispatches will return immediately. However a slow listener will cause the next event
// dispatch to block. This is the opposite behavior from Manager.
//
// Close will cancel all the goroutines. Subsequent calls to AddListener, RemoveListener, Close and
// Dispatch are no-ops.
type Target[T any] struct {
	initOnce         sync.Once
	ctx              context.Context
	cancel           context.CancelCauseFunc
	addListenerCh    chan addListenerEvent[T]
	removeListenerCh chan removeListenerEvent[T]
	dispatchCh       chan dispatchEvent[T]
	listeners        map[Handle]chan T
}

// AddListener adds a listener to the target.
func (t *Target[T]) AddListener(listener Listener[T]) Handle {
	t.init()

	// using a handle is necessary because you can't use a function as a map key.
	handle := Handle(uuid.NewString())

	select {
	case <-t.ctx.Done():
	case t.addListenerCh <- addListenerEvent[T]{listener, handle}:
	}

	return handle
}

// Close closes the event target. This can be called multiple times safely.
// Once closed the target cannot be used.
func (t *Target[T]) Close() {
	t.init()

	t.cancel(errors.New("target closed"))
}

// Dispatch dispatches an event to any listeners.
func (t *Target[T]) Dispatch(evt T) {
	t.init()

	select {
	case <-t.ctx.Done():
	case t.dispatchCh <- dispatchEvent[T]{evt}:
	}
}

// RemoveListener removes a listener from the target.
func (t *Target[T]) RemoveListener(handle Handle) {
	t.init()

	select {
	case <-t.ctx.Done():
	case t.removeListenerCh <- removeListenerEvent[T]{handle}:
	}
}

func (t *Target[T]) init() {
	t.initOnce.Do(func() {
		t.ctx, t.cancel = context.WithCancelCause(context.Background())
		t.addListenerCh = make(chan addListenerEvent[T], 1)
		t.removeListenerCh = make(chan removeListenerEvent[T], 1)
		t.dispatchCh = make(chan dispatchEvent[T], 1)
		t.listeners = map[Handle]chan T{}
		go t.run()
	})
}

func (t *Target[T]) run() {
	// listen for add/remove/dispatch events and call functions
	for {
		select {
		case <-t.ctx.Done():
			return
		case evt := <-t.addListenerCh:
			t.addListener(evt.listener, evt.handle)
		case evt := <-t.removeListenerCh:
			t.removeListener(evt.handle)
		case evt := <-t.dispatchCh:
			t.dispatch(evt.event)
		}
	}
}

// these functions are not thread-safe. They are intended to be called only by "run".

func (t *Target[T]) addListener(listener Listener[T], handle Handle) {
	ch := make(chan T, 1)
	t.listeners[handle] = ch
	// start a goroutine to send events to the listener
	go func() {
		for {
			select {
			case <-t.ctx.Done():
			case evt := <-ch:
				listener(evt)
			}
		}
	}()
}

func (t *Target[T]) removeListener(handle Handle) {
	ch, ok := t.listeners[handle]
	if !ok {
		// nothing to do since the listener doesn't exist
		return
	}
	// close the channel to kill the goroutine
	close(ch)
	delete(t.listeners, handle)
}

func (t *Target[T]) dispatch(evt T) {
	// loop over all the listeners and send the event to them
	for _, ch := range t.listeners {
		select {
		case <-t.ctx.Done():
			return
		case ch <- evt:
		}
	}
}
