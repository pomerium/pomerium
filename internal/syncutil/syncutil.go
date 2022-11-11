// Package syncutil contains methods for working with sync code.
package syncutil

import (
	"sync"
)

// A OnceMap is a collection sync.Onces accessible by a key. The zero value is usable.
type OnceMap[T comparable] struct {
	mu sync.Mutex
	m  map[T]*sync.Once
}

// Do runs f once.
func (o *OnceMap[T]) Do(key T, f func()) {
	o.mu.Lock()
	if o.m == nil {
		o.m = make(map[T]*sync.Once)
	}
	oo, ok := o.m[key]
	if !ok {
		oo = new(sync.Once)
		o.m[key] = oo
	}
	o.mu.Unlock()
	oo.Do(f)
}
