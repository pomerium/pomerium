package recording

import (
	"sync"
)

func newDynamicSemaphore(limit int) *dynamicSemaphore {
	return &dynamicSemaphore{
		limit: limit,
	}
}

type dynamicSemaphore struct {
	mu      sync.Mutex
	limit   int
	current int
}

func (s *dynamicSemaphore) TryAcquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current >= s.limit {
		return false
	}
	s.current++
	return true
}

func (s *dynamicSemaphore) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current > 0 {
		s.current--
	}
}

func (s *dynamicSemaphore) Resize(newLimit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limit = newLimit
}
