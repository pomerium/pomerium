package chanutil

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	t.Parallel()

	ch1, ch2, ch3 := make(chan int), make(chan int), make(chan int)
	go func() {
		for _, i := range []int{1, 2, 3} {
			ch1 <- i
		}
		close(ch1)
	}()
	go func() {
		for _, i := range []int{4, 5, 6} {
			ch2 <- i
		}
		close(ch2)
	}()
	go func() {
		for _, i := range []int{7, 8, 9} {
			ch3 <- i
		}
		close(ch3)
	}()
	out := Merge(ch1, ch2, ch3)
	var tmp []int
	for item := range out {
		tmp = append(tmp, item)
	}
	sort.Ints(tmp)
	assert.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, tmp)
}
