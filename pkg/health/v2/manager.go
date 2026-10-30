package healthv2

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

const (
	DefaultPollInterval = time.Second
	DefaultCheckTimeout = time.Second
)

type Options struct {
	PollInterval time.Duration
	CheckTimeout time.Duration
}

type checkerKey struct {
	group check.Group
	name  string
}

type checkerState struct {
	HealthChecker
	expected []check.CheckName
	inFlight atomic.Bool
	last     []check.Result
}

// Until a checker reports a result, each of its expected checks is reported as
// Unknown. Once Run's context is done every result is reported as Terminating
// without an error, and a check never goes back to Running.
type Manager struct {
	Options

	configureMu sync.Mutex
	cfg         *config.Options

	mu          sync.Mutex
	checkers    map[checkerKey]*checkerState
	configured  bool
	terminating bool

	sinks []HealthSink

	snapshot atomic.Pointer[Snapshot]
	lastPoll atomic.Int64
	pollNow  chan struct{}
}

func NewManager(opts Options) *Manager {
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.CheckTimeout <= 0 {
		opts.CheckTimeout = DefaultCheckTimeout
	}
	m := &Manager{
		Options:  opts,
		checkers: map[checkerKey]*checkerState{},
		pollNow:  make(chan struct{}, 1),
	}
	m.snapshot.Store(&Snapshot{})
	return m
}

// RegisterChecker must be called at startup, even if the checker's component
// does not exist yet; until it reports, the checker returns StatusUnknown results.
func (m *Manager) RegisterChecker(c HealthChecker) {
	m.configureMu.Lock()
	defer m.configureMu.Unlock()

	st := &checkerState{HealthChecker: c}
	if m.cfg != nil {
		st.expected = c.ConfigureChecks(m.cfg)
	}
	m.mu.Lock()
	m.checkers[checkerKey{c.Group(), c.Name()}] = st
	m.mu.Unlock()
	m.triggerPoll()
}

// RegisterSink must be called before Run.
func (m *Manager) RegisterSink(s HealthSink) {
	m.sinks = append(m.sinks, s)
}

// Close must be called after Run has returned.
func (m *Manager) Close() {
	for _, s := range m.sinks {
		s.Close()
	}
}

func (m *Manager) ConfigureChecks(opts *config.Options) {
	m.configureMu.Lock()
	defer m.configureMu.Unlock()

	m.cfg = opts
	for _, st := range m.allCheckers() {
		expected := st.ConfigureChecks(opts)
		m.mu.Lock()
		st.expected = expected
		m.mu.Unlock()
	}
	m.mu.Lock()
	m.configured = true
	m.mu.Unlock()
	m.triggerPoll()
}

func (m *Manager) Snapshot() Snapshot {
	return *m.snapshot.Load()
}

func (m *Manager) LastPoll() time.Time {
	ns := m.lastPoll.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (m *Manager) Run(ctx context.Context) error {
	t := time.NewTicker(m.PollInterval)
	defer t.Stop()
	for {
		m.poll(ctx)
		select {
		case <-ctx.Done():
			m.terminate()
			return ctx.Err()
		case <-t.C:
		case <-m.pollNow:
		}
	}
}

func (m *Manager) triggerPoll() {
	select {
	case m.pollNow <- struct{}{}:
	default:
	}
}

func (m *Manager) poll(ctx context.Context) {
	states := m.enabledCheckers()
	results := make([][]check.Result, len(states))
	var wg sync.WaitGroup
	for i, st := range states {
		wg.Go(func() { results[i] = m.checkWithTimeout(ctx, st) })
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	m.mu.Lock()
	for i, st := range states {
		st.last = results[i]
	}
	snap := m.buildSnapshotLocked()
	m.mu.Unlock()

	m.lastPoll.Store(time.Now().UnixNano())
	m.publish(snap)
}

// If the checker's previous Check has not returned yet, checkWithTimeout does
// not call it again and reports the timeout error again.
func (m *Manager) checkWithTimeout(ctx context.Context, st *checkerState) []check.Result {
	if !st.inFlight.CompareAndSwap(false, true) {
		return m.timedOut(st)
	}
	checkCtx, cancel := context.WithTimeout(ctx, m.CheckTimeout)
	defer cancel()

	done := make(chan []check.Result, 1)
	go func() {
		results := cloneResults(st.Check(checkCtx))
		st.inFlight.Store(false)
		done <- results
	}()

	select {
	case results := <-done:
		return results
	case <-checkCtx.Done():
		if ctx.Err() == nil {
			log.Ctx(ctx).Warn().
				Str("group", string(st.Group())).
				Str("checker", st.Name()).
				Msg("health check timed out")
		}
		return m.timedOut(st)
	}
}

func (m *Manager) timedOut(st *checkerState) []check.Result {
	err := fmt.Errorf("health check %s/%s timed out", st.Group(), st.Name())
	m.mu.Lock()
	last := st.resultsLocked()
	m.mu.Unlock()

	results := make([]check.Result, len(last))
	for i, r := range last {
		results[i] = check.Result{Name: r.Name, Status: r.Status, Err: err}
	}
	return results
}

func cloneResults(results []check.Result) []check.Result {
	out := slices.Clone(results)
	for i := range out {
		out[i].Attrs = slices.Clone(out[i].Attrs)
	}
	return out
}

func (m *Manager) terminate() {
	m.mu.Lock()
	m.terminating = true
	snap := m.buildSnapshotLocked()
	m.mu.Unlock()
	m.publish(snap)
}

func (m *Manager) buildSnapshotLocked() Snapshot {
	snap := Snapshot{Configured: m.configured, Terminating: m.terminating}
	for key, st := range m.checkers {
		if !st.enabledLocked() {
			continue
		}
		results := st.resultsLocked()
		if m.terminating {
			results = terminated(results)
		}
		snap.Checkers = append(snap.Checkers, CheckerStatus{Group: key.group, Name: key.name, Results: results})
	}
	slices.SortFunc(snap.Checkers, func(a, b CheckerStatus) int {
		return cmp.Or(cmp.Compare(a.Group, b.Group), cmp.Compare(a.Name, b.Name))
	})
	return snap
}

func terminated(results []check.Result) []check.Result {
	results = cloneResults(results)
	for i := range results {
		results[i].Status = check.StatusTerminating
		results[i].Err = nil
	}
	return results
}

func (m *Manager) publish(snap Snapshot) {
	if prev := m.snapshot.Swap(&snap); prev.Equal(snap) {
		return
	}
	for _, s := range m.sinks {
		s.Notify(snap)
	}
}

func (m *Manager) allCheckers() []*checkerState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Collect(maps.Values(m.checkers))
}

func (m *Manager) enabledCheckers() []*checkerState {
	m.mu.Lock()
	defer m.mu.Unlock()
	var states []*checkerState
	for _, st := range m.checkers {
		if st.enabledLocked() {
			states = append(states, st)
		}
	}
	return states
}

func (st *checkerState) enabledLocked() bool {
	return len(st.expected) > 0
}

func (st *checkerState) resultsLocked() []check.Result {
	results := slices.Clone(st.last)
	for _, name := range st.expected {
		if !slices.ContainsFunc(st.last, func(r check.Result) bool { return r.Name == name }) {
			results = append(results, check.Result{Name: name})
		}
	}
	return results
}
