// Package atomicutil contains functions for working with the atomic package.
package atomicutil

import "sync/atomic"

// Value is a generic atomic.Value.
type Value[T any] struct {
	value atomic.Value
}

// NewValue creates a new Value.
func NewValue[T any](init T) *Value[T] {
	v := new(Value[T])
	v.value.Store(init)
	return v
}

// Load loads the value atomically.
func (v *Value[T]) Load() T {
	var def T
	if v == nil {
		return def
	}

	cur := v.value.Load()
	if cur == nil {
		return def
	}
	return cur.(T)
}

// Store stores the value atomically.
func (v *Value[T]) Store(val T) {
	v.value.Store(val)
}

// Swap swaps the value atomically.
func (v *Value[T]) Swap(val T) T {
	old, _ := v.value.Swap(val).(T)
	return old
}

// Swap swaps the value atomically.
func (v *Value[T]) CompareAndSwap(old, n T) bool {
	return v.value.CompareAndSwap(old, n)
}
