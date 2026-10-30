package healthv2

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

func running(name string, attrs ...check.Attr) check.Result {
	return check.Result{Name: check.CheckName(name), Status: check.StatusRunning, Attrs: attrs}
}

func terminating(name string) check.Result {
	return check.Result{Name: check.CheckName(name), Status: check.StatusTerminating}
}

func failing(name string, status check.Status, msg string) check.Result {
	return check.Result{Name: check.CheckName(name), Status: status, Err: errors.New(msg)}
}

type fakeChecker struct {
	group    check.Group
	name     string
	expected []check.CheckName
	enabled  func(*config.Options) bool
	checkFn  func(context.Context) []check.Result
	results  atomic.Pointer[[]check.Result]
	calls    atomic.Int32
}

func newChecker(group check.Group, name string, results ...check.Result) *fakeChecker {
	c := &fakeChecker{group: group, name: name}
	for _, r := range results {
		c.expected = append(c.expected, r.Name)
	}
	c.set(results...)
	return c
}

func (c *fakeChecker) set(results ...check.Result) {
	c.results.Store(&results)
}

func (c *fakeChecker) Group() check.Group { return c.group }

func (c *fakeChecker) Name() string { return c.name }

func (c *fakeChecker) ConfigureChecks(opts *config.Options) []check.CheckName {
	if c.enabled != nil && !c.enabled(opts) {
		return nil
	}
	return c.expected
}

func (c *fakeChecker) Check(ctx context.Context) []check.Result {
	c.calls.Add(1)
	if c.checkFn != nil {
		return c.checkFn(ctx)
	}
	return *c.results.Load()
}

func checkerStatus(group check.Group, name string, results ...check.Result) CheckerStatus {
	return CheckerStatus{Group: group, Name: name, Results: results}
}

type recordingSink struct {
	mu     sync.Mutex
	snaps  []Snapshot
	closed bool
}

func (s *recordingSink) Notify(snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snaps = append(s.snaps, snap)
}

func (s *recordingSink) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.snaps)
}
