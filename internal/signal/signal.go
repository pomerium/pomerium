// Package signal provides mechanism for notifying multiple listeners when something happened.
package signal

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
)

type Options struct {
	logger *zerolog.Logger
}

func (o *Options) Apply(opts ...Option) {
	for _, opt := range opts {
		opt(o)
	}
}

type Option func(o *Options)

func defaultOptions() *Options {
	nopL := zerolog.Nop()
	return &Options{
		logger: &nopL,
	}
}

func WithLogger(l *zerolog.Logger) Option {
	return func(o *Options) {
		o.logger = l
	}
}

// A Signal is used to let multiple listeners know when something happened.
type Signal struct {
	mu  sync.Mutex
	chs map[chan context.Context]struct{}
	*Options
}

// New creates a new Signal.
func New(opts ...Option) *Signal {
	options := defaultOptions()
	options.Apply(opts...)
	return &Signal{
		Options: options,
		chs:     make(map[chan context.Context]struct{}),
	}
}

// Broadcast signals all the listeners. Broadcast never blocks.
func (s *Signal) Broadcast(ctx context.Context) {
	s.mu.Lock()
	for ch := range s.chs {
		select {
		case ch <- ctx:
		default:
			s.logger.Warn().Ctx(ctx).Msg("failed to broadcast signal update, buffer full")
		}
	}
	s.mu.Unlock()
}

// Bind creates a new listening channel bound to the signal. The channel used has a size of 1
// and any given broadcast will signal at least one event, but may signal more than one.
func (s *Signal) Bind() chan context.Context {
	ch := make(chan context.Context, 1)
	s.mu.Lock()
	s.chs[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

// Unbind stops the listening channel bound to the signal.
func (s *Signal) Unbind(ch chan context.Context) {
	s.mu.Lock()
	delete(s.chs, ch)
	s.mu.Unlock()
}
