package atomicutil

import (
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
