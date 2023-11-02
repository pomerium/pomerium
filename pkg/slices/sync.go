package slices

import "sync"

// SafeSlice is a thread safe slice.
type SafeSlice[E any] struct {
	mu    sync.RWMutex
	slice []E
}

// NewSafeSlice creates a new SafeSlice.
func NewSafeSlice[E any]() *SafeSlice[E] {
	return &SafeSlice[E]{}
}

// Append appends e to the slice.
func (s *SafeSlice[E]) Append(e E) {
	s.mu.Lock()
	s.slice = append(s.slice, e)
	s.mu.Unlock()
}

// Get gets the slice.
func (s *SafeSlice[E]) Get() []E {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c := make([]E, len(s.slice))
	copy(c, s.slice)
	return c
}
