package sets

import "sync"

// A Hash is a set implemented via a map.
type Hash[T comparable] struct {
	mu sync.RWMutex
	m  map[T]struct{}
}

// NewHash creates a new Hash set.
func NewHash[T comparable](initialValues ...T) *Hash[T] {
	s := &Hash[T]{
		m: make(map[T]struct{}),
	}
	s.Add(initialValues...)
	return s
}

// Add adds a value to the set.
func (s *Hash[T]) Add(elements ...T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, element := range elements {
		s.m[element] = struct{}{}
	}
}

// Has returns true if the element is in the set.
func (s *Hash[T]) Has(element T) bool {
	s.mu.RLock()
	_, ok := s.m[element]
	s.mu.RUnlock()
	return ok
}

// Size returns the size of the set.
func (s *Hash[T]) Size() int {
	s.mu.RLock()
	l := len(s.m)
	s.mu.RUnlock()
	return l
}
