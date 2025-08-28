package cluster

import "sync"

// A Sink receives values and sends them to bound channels.
type Sink[T any] struct {
	mu         sync.Mutex
	channels   map[chan T]struct{}
	hasCurrent bool
	current    T
}

// Bind creates a new channel that will receive an values sent to the sink.
// If a value has previously been sent it will be sent immediately on the
// channel.
func (s *Sink[T]) Bind() chan T {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan T, 1)
	if s.channels == nil {
		s.channels = make(map[chan T]struct{})
	}
	s.channels[ch] = struct{}{}
	if s.hasCurrent {
		ch <- s.current
	}
	return ch
}

// Send sends a value to any listening channels. It also stores the value
// and will send it to any newly created channels. Only the last value is
// stored.
func (s *Sink[T]) Send(v T) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.hasCurrent = true
	s.current = v

	for ch := range s.channels {
	inner_loop:
		for {
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- v:
				break inner_loop
			default:
			}
		}
	}
}

// Unbind removes a channel from the listeners so it will no longer receive new
// values.
func (s *Sink[T]) Unbind(ch chan T) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.channels, ch)
}
