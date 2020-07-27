// Package signal provides mechanism for notifying multiple listeners when something happened.
package signal

import (
	"sync"
)

// A Signal is used to let multiple listeners know when something happened.
type Signal struct {
	mu  sync.Mutex
	chs map[chan struct{}]struct{}
}

// New creates a new Signal.
func New() *Signal {
	return &Signal{
		chs: make(map[chan struct{}]struct{}),
	}
}

// Broadcast signals all the listeners. Broadcast never blocks.
func (s *Signal) Broadcast() {
	s.mu.Lock()
	for ch := range s.chs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	s.mu.Unlock()
}

// Bind creates a new listening channel bound to the signal. The channel used has a size of 1
// and any given broadcast will signal at least one event, but may signal more than one.
func (s *Signal) Bind() chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.chs[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

// Unbind stops the listening channel bound to the signal.
func (s *Signal) Unbind(ch chan struct{}) {
	s.mu.Lock()
	delete(s.chs, ch)
	s.mu.Unlock()
}
