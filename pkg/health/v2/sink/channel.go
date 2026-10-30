package sink

import (
	"sync"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

// Channel signals OnReady and OnTerminating each at most once.
type Channel struct {
	mu              sync.Mutex
	closed          bool
	sentReady       bool
	sentTerminating bool

	onReady       chan struct{}
	onTerminating chan struct{}
}

var _ healthv2.HealthSink = (*Channel)(nil)

func NewChannel() *Channel {
	return &Channel{
		onReady:       make(chan struct{}, 1),
		onTerminating: make(chan struct{}, 1),
	}
}

func (c *Channel) OnReady() <-chan struct{} { return c.onReady }

func (c *Channel) OnTerminating() <-chan struct{} { return c.onTerminating }

func (c *Channel) Notify(snap healthv2.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if !c.sentReady && snap.Ready() {
		c.sentReady = true
		c.onReady <- struct{}{}
	}
	if !c.sentTerminating && snap.AllTerminating() {
		c.sentTerminating = true
		c.onTerminating <- struct{}{}
	}
}

func (c *Channel) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.onReady)
	close(c.onTerminating)
}
