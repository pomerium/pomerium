package events

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

type (
	// A Listener is a function that listens for events of type T.
	Listener[T any] func(ctx context.Context, event T)
	// A Handle represents a listener.
	Handle string

	dispatchEvent[T any] struct {
		ctx   context.Context
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
// Each listener is run in its own goroutine.
//
// A slow listener will cause the next event dispatch to block. This is the
// opposite behavior from Manager.
//
// Close will remove and cancel all listeners.
type Target[T any] struct {
	mu        sync.RWMutex
	listeners map[Handle]targetListener[T]
}

// AddListener adds a listener to the target.
func (t *Target[T]) AddListener(listener Listener[T]) Handle {
	// using a handle is necessary because you can't use a function as a map key.
	h := Handle(uuid.NewString())
	tl := newTargetListener(listener)

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.listeners == nil {
		t.listeners = make(map[Handle]targetListener[T])
	}

	t.listeners[h] = tl
	return h
}

// Close closes the event target. This can be called multiple times safely.
func (t *Target[T]) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, tl := range t.listeners {
		tl.close()
	}
	t.listeners = nil
}

// Dispatch dispatches an event to all listeners.
func (t *Target[T]) Dispatch(ctx context.Context, evt T) {
	// store all the listeners in a slice so we don't hold the lock while dispatching
	var tls []targetListener[T]
	t.mu.RLock()
	tls = make([]targetListener[T], 0, len(t.listeners))
	for _, tl := range t.listeners {
		tls = append(tls, tl)
	}
	t.mu.RUnlock()

	// Because we're outside of the lock it's possible we may dispatch to a listener
	// that's been removed if Dispatch and RemoveListener are called from separate
	// goroutines. There should be no possibility of a deadlock however.

	for _, tl := range tls {
		tl.dispatch(dispatchEvent[T]{ctx: ctx, event: evt})
	}
}

// RemoveListener removes a listener from the target.
func (t *Target[T]) RemoveListener(handle Handle) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.listeners == nil {
		t.listeners = make(map[Handle]targetListener[T])
	}

	tl, ok := t.listeners[handle]
	if !ok {
		return
	}

	tl.close()
	delete(t.listeners, handle)
}

// A targetListener starts a goroutine that pulls events from "ch" and
// calls the listener for each event.
//
// The goroutine is stopped when ".close()" is called. We don't rely
// on closing "ch" because sending to a closed channel results in a
// panic. Instead we signal closing via "ctx.Done()".
type targetListener[T any] struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	ch       chan dispatchEvent[T]
	listener Listener[T]
}

func newTargetListener[T any](listener Listener[T]) targetListener[T] {
	li := targetListener[T]{}
	li.ctx, li.cancel = context.WithCancelCause(context.Background())
	li.ch = make(chan dispatchEvent[T])
	li.listener = listener
	go li.run()
	return li
}

func (li targetListener[T]) close() {
	li.cancel(errors.New("events target listener closed"))
}

func (li targetListener[T]) dispatch(evt dispatchEvent[T]) {
	select {
	case <-li.ctx.Done():
	case li.ch <- evt:
	}
}

func (li targetListener[T]) run() {
	for {
		select {
		case <-li.ctx.Done():
			return
		case evt := <-li.ch:
			li.listener(evt.ctx, evt.event)
		}
	}
}
