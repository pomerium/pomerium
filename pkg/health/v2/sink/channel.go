package sink

import (
	"context"
	"sync"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

type Channel struct {
	mu        sync.Mutex
	sentReady bool

	onReady chan struct{}
}

var _ healthv2.HealthSink = (*Channel)(nil)

func NewChannel() *Channel {
	return &Channel{onReady: make(chan struct{}, 1)}
}

// OnReady is signaled at most once.
func (c *Channel) OnReady() <-chan struct{} { return c.onReady }

func (c *Channel) Run() {}

func (c *Channel) Shutdown(context.Context) {}

func (c *Channel) Notify(snap healthv2.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sentReady && snap.Ready() {
		c.sentReady = true
		c.onReady <- struct{}{}
	}
}
