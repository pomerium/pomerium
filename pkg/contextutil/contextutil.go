// Package contextutil contains functions for working with contexts.
package contextutil

import (
	"context"
	"time"
)

type mergedCtx struct {
	ctx1, ctx2 context.Context

	doneCtx    context.Context
	doneCancel context.CancelFunc
}

// Merge merges two contexts into a single context.
func Merge(ctx1, ctx2 context.Context) (context.Context, context.CancelFunc) {
	mc := &mergedCtx{
		ctx1: ctx1,
		ctx2: ctx2,
	}
	mc.doneCtx, mc.doneCancel = context.WithCancel(context.Background())
	go func() {
		select {
		case <-ctx1.Done():
		case <-ctx2.Done():
		case <-mc.doneCtx.Done():
		}
		mc.doneCancel()
	}()
	return mc, mc.doneCancel
}

func (mc *mergedCtx) Deadline() (deadline time.Time, ok bool) {
	if deadline, ok = mc.ctx1.Deadline(); ok {
		return deadline, ok
	}
	if deadline, ok = mc.ctx2.Deadline(); ok {
		return deadline, ok
	}
	return mc.doneCtx.Deadline()
}

func (mc *mergedCtx) Done() <-chan struct{} {
	return mc.doneCtx.Done()
}

func (mc *mergedCtx) Err() error {
	if err := mc.ctx1.Err(); err != nil {
		return mc.ctx1.Err()
	}
	if err := mc.ctx2.Err(); err != nil {
		return mc.ctx2.Err()
	}
	return mc.doneCtx.Err()
}

func (mc *mergedCtx) Value(key any) any {
	if value := mc.ctx1.Value(key); value != nil {
		return value
	}
	if value := mc.ctx2.Value(key); value != nil {
		return value
	}
	return mc.doneCtx.Value(key)
}
