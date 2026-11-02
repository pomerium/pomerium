package sink

import (
	"sync/atomic"
	"time"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

type pollProgress interface {
	LastPoll() time.Time
}

type latestSnapshot struct {
	snap   atomic.Pointer[healthv2.Snapshot]
	signal chan struct{}
}

func newLatestSnapshot() *latestSnapshot {
	l := &latestSnapshot{signal: make(chan struct{}, 1)}
	l.snap.Store(&healthv2.Snapshot{})
	return l
}

// store never blocks.
func (l *latestSnapshot) store(s healthv2.Snapshot) {
	l.snap.Store(&s)
	select {
	case l.signal <- struct{}{}:
	default:
	}
}

// load returns the newest snapshot; a reader that falls behind skips older ones.
func (l *latestSnapshot) load() healthv2.Snapshot {
	return *l.snap.Load()
}
