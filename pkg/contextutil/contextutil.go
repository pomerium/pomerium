// Package contextutil contains functions for working with contexts.
package contextutil

import (
	"context"
)

type mergedCtx struct {
	context.Context
	ctx1, ctx2 context.Context
}

// Merge merges two contexts into a single context.
func Merge(ctx1, ctx2 context.Context) (context.Context, context.CancelFunc) {
	mc := &mergedCtx{
		ctx1: ctx1,
		ctx2: ctx2,
	}
	var cancel context.CancelCauseFunc
	mc.Context, cancel = context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-ctx1.Done():
			cancel(context.Cause(ctx1))
		case <-ctx2.Done():
			cancel(context.Cause(ctx2))
		case <-mc.Done():
		}
	}()

	var cleanup []context.CancelFunc
	if deadline, ok := ctx1.Deadline(); ok {
		var cancel context.CancelFunc
		mc.Context, cancel = context.WithDeadline(mc.Context, deadline)
		cleanup = append(cleanup, cancel)
	}
	if deadline, ok := ctx2.Deadline(); ok {
		var cancel context.CancelFunc
		mc.Context, cancel = context.WithDeadline(mc.Context, deadline)
		cleanup = append(cleanup, cancel)
	}

	return mc, func() {
		cancel(context.Canceled)
		for _, cancel := range cleanup {
			cancel()
		}
	}
}

func (mc *mergedCtx) Value(key any) any {
	if value := mc.Context.Value(key); value != nil {
		return value
	}
	if value := mc.ctx1.Value(key); value != nil {
		return value
	}
	if value := mc.ctx2.Value(key); value != nil {
		return value
	}
	return nil
}
