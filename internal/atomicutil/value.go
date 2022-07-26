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
	return v.value.Load().(T)
}

// Store stores the value atomically.
func (v *Value[T]) Store(val T) {
	v.value.Store(val)
}
