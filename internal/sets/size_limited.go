package sets

import (
	"iter"
	"maps"
)

// A SizeLimited is a Set which is limited to a given size. Once
// the capacity is reached an element will be removed at random.
type SizeLimited[T comparable] struct {
	m        map[T]struct{}
	capacity int
}

// NewSizeLimited create a new SizeLimited.
func NewSizeLimited[T comparable](capacity int) *SizeLimited[T] {
	return &SizeLimited[T]{
		m:        make(map[T]struct{}),
		capacity: capacity,
	}
}

// Insert adds an element to the set.
func (s *SizeLimited[T]) Insert(element T) {
	s.m[element] = struct{}{}
	for len(s.m) > s.capacity {
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
}

// Items returns an iterator over the items in the set. Order is not specified.
func (s *SizeLimited[T]) Items() iter.Seq[T] {
	return maps.Keys(s.m)
}
