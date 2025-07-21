package atomicutil

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValue(t *testing.T) {
	v := NewValue(5)
	assert.Equal(t, 5, v.Load())

	t.Run("nil", func(t *testing.T) {
		var v *Value[int]
		assert.Equal(t, 0, v.Load())
	})
	t.Run("default", func(t *testing.T) {
		var v Value[int]
		assert.Equal(t, 0, v.Load())
	})
}

func TestStore(t *testing.T) {
	v := NewValue(5)
	v.Store(42)
	assert.Equal(t, 42, v.Load())
}

func TestSwap(t *testing.T) {
	v := NewValue(42)
	v.Swap(33)
	assert.Equal(t, 33, v.Load())
}

func TestCompareAndSwap(t *testing.T) {
	v := NewValue(42)

	swapped := v.CompareAndSwap(42, 33)
	assert.Equal(t, true, swapped)
	assert.Equal(t, 33, v.Load())

	swapped = v.CompareAndSwap(42, 33)
	assert.Equal(t, false, swapped)
	assert.Equal(t, 33, v.Load())
}

// This is just to illustrate how we should use atomic.Pointer[T] instead.
func TestWithPointer(t *testing.T) {
	var withUtil *Value[int]
	var withPointer atomic.Pointer[int]

	// This becomes the zero value.
	assert.NotNil(t, withUtil.Load())

	// This is nil.
	assert.Nil(t, withPointer.Load())
}
