package contextutil

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	type key string
	t.Run("value", func(t *testing.T) {
		type contextKey string
		k1 := contextKey("key1")
		k2 := contextKey("key2")

		ctx1 := context.WithValue(t.Context(), k1, "value1")
		ctx2 := context.WithValue(t.Context(), k2, "value2")
		ctx3, _ := Merge(ctx1, ctx2)
		assert.Equal(t, "value1", ctx3.Value(k1))
		assert.Equal(t, "value2", ctx3.Value(k2))
	})
	t.Run("cancel", func(t *testing.T) {
		ctx1, cancel1 := context.WithCancel(t.Context())
		defer cancel1()
		ctx2, cancel2 := context.WithCancel(t.Context())
		ctx3, _ := Merge(ctx1, ctx2)
		cancel2()
		assert.Eventually(t, func() bool {
			select {
			case <-ctx3.Done():
				return true
			default:
				return false
			}
		}, time.Second, time.Millisecond*100)
	})
}
