// Package contextutil contains functions for working with contexts.
package contextutil

import (
	"context"
	"slices"
	"time"
)

type mergedCtx struct {
	ctxs    []context.Context
	doneCtx context.Context
}

// Merge merges two contexts into a single context.
func Merge(ctxs ...context.Context) (context.Context, context.CancelCauseFunc) {
	mc := &mergedCtx{ctxs: ctxs}

	var cancel context.CancelCauseFunc
	mc.doneCtx, cancel = context.WithCancelCause(context.Background())

	var cleanup []func() bool
	for _, ctx := range ctxs {
		// if a parent context completes,
		// we will cancel the done context with the cause
		cleanup = append(cleanup,
			context.AfterFunc(ctx, func() {
				cancel(context.Cause(ctx))
			}))
	}

	return mc, func(cause error) {
		cancel(cause)
		for _, f := range cleanup {
			f()
		}
	}
}

func (mc *mergedCtx) Deadline() (time.Time, bool) {
	var tm time.Time
	var ok bool
	// find the soonest deadline
	for _, ctx := range mc.ctxs {
		if ctxTm, ctxOK := ctx.Deadline(); ctxOK && (!ok || ctxTm.Before(tm)) {
			tm = ctxTm
			ok = true
		}
	}
	return tm, ok
}

func (mc *mergedCtx) Done() <-chan struct{} {
	return mc.doneCtx.Done()
}

func (mc *mergedCtx) Err() error {
	return mc.doneCtx.Err()
}

func (mc *mergedCtx) Value(key any) any {
	// cancel cause is propogated as a value,
	// so we need to check the done context as well
	if value := mc.doneCtx.Value(key); value != nil {
		return value
	}

	// go in reverse order through the contexts
	// so the last context takes precedence
	for _, ctx := range slices.Backward(mc.ctxs) {
		if value := ctx.Value(key); value != nil {
			return value
		}
	}
	return nil
}
