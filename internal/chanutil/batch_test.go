package chanutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBatch(t *testing.T) {
	t.Parallel()

	ch1 := make(chan int)
	go func() {
		for _, i := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
			ch1 <- i
		}
		close(ch1)
	}()

	ch2 := Batch(ch1, WithBatchMaxWait(time.Millisecond*10), WithBatchMaxSize(3))
	assert.Equal(t, []int{1, 2, 3}, <-ch2)
	assert.Equal(t, []int{4, 5, 6}, <-ch2)
	assert.Equal(t, []int{7, 8, 9}, <-ch2)
	assert.Equal(t, []int{10}, <-ch2)
	assert.Equal(t, []int(nil), <-ch2)
}
