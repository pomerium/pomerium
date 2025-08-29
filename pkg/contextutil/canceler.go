package contextutil

import (
	"context"
	"sync"
)

// A canceler can be used to cancel a context with the given cause.
// After the context is canceled a new context is created and any
// subsequent calls to .Context() will return the new context.
type Canceler interface {
	// Cancel cancels the context returned from Context(). It then
	// creates a new context that will be canceled on subsequent
	// calls to Cancel.
	Cancel(cause error)
	// Context returns the current cancellation context.
	Context() context.Context
}

type canceler struct {
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelCauseFunc
}

// NewCanceler returns a new Canceler.
func NewCanceler() Canceler {
	c := &canceler{}
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	return c
}

func (c *canceler) Cancel(cause error) {
	c.mu.Lock()
	c.cancel(cause)
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	c.mu.Unlock()
}

func (c *canceler) Context() context.Context {
	c.mu.RLock()
	ctx := c.ctx
	c.mu.RUnlock()
	return ctx
}
