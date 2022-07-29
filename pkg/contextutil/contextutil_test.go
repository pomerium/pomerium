package contextutil

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		ctx1 := context.WithValue(context.Background(), "key1", "value1")
		ctx2 := context.WithValue(context.Background(), "key2", "value2")
		ctx3, _ := Merge(ctx1, ctx2)
		assert.Equal(t, "value1", ctx3.Value("key1"))
		assert.Equal(t, "value2", ctx3.Value("key2"))
	})
	t.Run("cancel", func(t *testing.T) {
		ctx1, cancel1 := context.WithCancel(context.Background())
		defer cancel1()
		ctx2, cancel2 := context.WithCancel(context.Background())
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
