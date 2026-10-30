package healthv2

import (
	"context"
	"sync"
	"sync/atomic"
)

func pass(details map[string]string) Condition {
	return Condition{OK: true, Info: Info{Details: details}}
}

func fail(reason string) Condition {
	return Condition{Info: Info{Reason: reason}}
}

func checkerStatus(service ServiceID, name string, ready, healthy Condition) CheckerStatus {
	return CheckerStatus{Service: service, Name: name, Initialized: pass(nil), Ready: ready, Healthy: healthy}
}

func uninitialized(c CheckerStatus, reason string) CheckerStatus {
	c.Initialized = fail(reason)
	c.Ready = fail(reason)
	return c
}

func running(service ServiceID, name string) CheckerStatus {
	return checkerStatus(service, name, pass(nil), pass(nil))
}

type fakeChecker struct {
	service     ServiceID
	name        string
	initialized atomic.Pointer[Condition]
	ready       atomic.Pointer[Condition]
	healthy     atomic.Pointer[Condition]
	readyFn     func(context.Context)
	calls       atomic.Int32
}

func newChecker(group ServiceID, name string) *fakeChecker {
	c := &fakeChecker{service: group, name: name}
	c.setInitialized(pass(nil))
	c.set(pass(nil), pass(nil))
	return c
}

func (c *fakeChecker) setInitialized(initialized Condition) {
	c.initialized.Store(&initialized)
}

func (c *fakeChecker) set(ready, healthy Condition) {
	c.ready.Store(&ready)
	c.healthy.Store(&healthy)
}

func (c *fakeChecker) Service() ServiceID { return c.service }

func (c *fakeChecker) Component() string { return c.name }

func (c *fakeChecker) Initialized(context.Context) (bool, Info) {
	i := c.initialized.Load()
	return i.OK, i.Info
}

func (c *fakeChecker) Ready(ctx context.Context) (bool, Info) {
	c.calls.Add(1)
	if c.readyFn != nil {
		c.readyFn(ctx)
	}
	r := c.ready.Load()
	return r.OK, r.Info
}

func (c *fakeChecker) Healthy(context.Context) (bool, Info) {
	h := c.healthy.Load()
	return h.OK, h.Info
}

func (c *fakeChecker) OnShutdown(context.Context, error) {
	// TODO : health check v2
}

type recordingSink struct {
	mu      sync.Mutex
	snaps   []Snapshot
	started bool
}

func (s *recordingSink) Run() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = true
}

func (s *recordingSink) Notify(snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snaps = append(s.snaps, snap)
}

func (s *recordingSink) Shutdown(context.Context) {}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.snaps)
}

func (s *recordingSink) last() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snaps[len(s.snaps)-1]
}
