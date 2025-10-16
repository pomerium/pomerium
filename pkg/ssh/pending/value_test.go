package pending

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPendingValueMutable(t *testing.T) {
	assert := assert.New(t)

	p := NewPending[string]()
	p.Resolve("hello")
	v := <-p.Get()
	assert.Equal("hello", v)

	p.Resolve("world")
	v2 := <-p.Get()
	assert.Equal("world", v2)
}

func TestPendingValueGoroutineSafe(t *testing.T) {
	p := NewPending[int]()
	var wg sync.WaitGroup
	n := 10
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			p.Resolve(i + 1)
		}()
	}
	wg.Wait()
	v := <-p.Get()
	assert.NotEqual(t, 0, v)
}
