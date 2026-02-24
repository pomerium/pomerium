package recording

import (
	"sync"

	"golang.org/x/sync/semaphore"
)

const maxInFlight = 10000

// DynamicSemaphore is a semaphore whose limit can be changed at runtime.
type DynamicSemaphore interface {
	TryAcquire() bool
	Release()
	Resize(newLimit int)
}

// reservationSemaphore backs onto a large fixed-capacity weighted semaphore and
// reserves the difference between that capacity and the current limit.
// When a resize cannot immediately reclaim slots (because they are held),
// it tracks the deficit and reclaims slots as they are released.
type reservationSemaphore struct {
	mu    sync.Mutex
	limit int64
	owed  int64
	sem   *semaphore.Weighted
}

var _ DynamicSemaphore = (*reservationSemaphore)(nil)

// NewReservationSemaphore creates a DynamicSemaphore that eagerly reserves
// capacity on resize using owed-slot tracking.
func NewReservationSemaphore(limit int) DynamicSemaphore {
	s := &reservationSemaphore{
		limit: int64(limit),
		sem:   semaphore.NewWeighted(maxInFlight),
	}
	if reserved := int64(maxInFlight) - s.limit; reserved > 0 {
		s.sem.TryAcquire(reserved)
	}
	return s
}

func (s *reservationSemaphore) TryAcquire() bool {
	return s.sem.TryAcquire(1)
}

func (s *reservationSemaphore) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owed > 0 {
		s.owed--
		return
	}
	s.sem.Release(1)
}

func (s *reservationSemaphore) Resize(newLimit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	diff := int64(newLimit) - s.limit
	switch {
	case diff > 0:
		fromOwed := min(s.owed, diff)
		s.owed -= fromOwed
		if remaining := diff - fromOwed; remaining > 0 {
			s.sem.Release(remaining)
		}
	case diff < 0:
		need := -diff
		for need > 0 && s.sem.TryAcquire(1) {
			need--
		}
		s.owed += need
	}
	s.limit = int64(newLimit)
}
