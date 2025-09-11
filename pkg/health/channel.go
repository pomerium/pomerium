package health

import "sync"

type ChannelProvider struct {
	expected      map[Check]struct{}
	tr            Tracker
	onReady       chan struct{}
	onTerminating chan struct{}

	sendReady      func()
	sendTerminated func()
}

var _ Provider = (*ChannelProvider)(nil)

func NewChannelProvider(
	tr Tracker,
	opts ...CheckOption,
) *ChannelProvider {
	o := CheckOptions{}
	o.Apply(opts...)

	c := &ChannelProvider{
		tr:            tr,
		expected:      o.expected,
		onReady:       make(chan struct{}, 1),
		onTerminating: make(chan struct{}, 1),
	}

	c.sendReady = sync.OnceFunc(func() {
		c.onReady <- struct{}{}
	})

	c.sendTerminated = sync.OnceFunc(func() {
		c.onTerminating <- struct{}{}
	})

	return c
}

func (c *ChannelProvider) Close() {
	close(c.onReady)
	close(c.onTerminating)
}

func (c *ChannelProvider) OnReady() <-chan struct{} {
	return c.onReady
}

func (c *ChannelProvider) OnTerminating() <-chan struct{} {
	return c.onTerminating
}

func (c *ChannelProvider) ReportStatus(_ Check, _ Status, _ ...Attr) {
	recs := c.tr.GetRecords()
	ready := true
	terminated := true

	for id := range c.expected {
		rec, ok := recs[id]
		if !ok {
			ready = false
			terminated = false
			break
		}
		if rec.err != nil {
			ready = false
			terminated = false
			break
		}
		if rec.status != StatusRunning {
			ready = false
		}
		if rec.status != StatusTerminating {
			terminated = false
		}
	}
	if ready {
		c.sendReady()
	}
	if terminated {
		c.sendTerminated()
	}
}

func (c *ChannelProvider) ReportError(_ Check, _ error, _ ...Attr) {
}
