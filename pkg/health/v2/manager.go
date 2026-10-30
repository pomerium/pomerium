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

	"github.com/pomerium/pomerium/internal/log"
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
	service ServiceID
	name    string
}

type checkerState struct {
	ServiceEvaluator
	inFlight atomic.Bool
	last     CheckerStatus
}

type Manager struct {
	Options

	mu       sync.Mutex
	checkers map[checkerKey]*checkerState

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

// RegisterHealthChecker must be called before Run.
func (m *Manager) RegisterHealthChecker(c ServiceEvaluator) {
	st := &checkerState{
		ServiceEvaluator: c,
		// The checker must be reported not initialized, not ready and not healthy if it is not yet polled.
		last: CheckerStatus{Service: c.Service(), Name: c.Component()},
	}
	m.mu.Lock()
	m.checkers[checkerKey{c.Service(), c.Component()}] = st
	m.mu.Unlock()
	m.triggerPoll()
}

// RegisterSink registers an integration like HTTP probes, systemd, metrics, etc
// as detinations of the health checkers registered by this manager.
//
//	!! Must be called before Run.
func (m *Manager) RegisterSink(s HealthSink) {
	m.sinks = append(m.sinks, s)
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

// Run polls for the life of the process and never returns. Canceling ctx does
// not stop polling.
func (m *Manager) Run(ctx context.Context) {
	for _, s := range m.sinks {
		s.Run()
	}
	ctx = context.WithoutCancel(ctx)
	t := time.NewTicker(m.PollInterval)
	for {
		m.poll(ctx)
		select {
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
	states := m.allCheckers()
	statuses := make([]CheckerStatus, len(states))
	var wg sync.WaitGroup
	for i, st := range states {
		wg.Go(func() { statuses[i] = m.checkWithTimeout(ctx, st) })
	}
	wg.Wait()

	m.mu.Lock()
	for i, st := range states {
		st.last = statuses[i]
	}
	snap := m.buildSnapshotLocked()
	m.mu.Unlock()

	m.lastPoll.Store(time.Now().UnixNano())
	m.publish(snap)
}

// checkWithTimeout calls Initialized, Ready and Healthy under one CheckTimeout
// ctx. A checker that does not return in time is reported not initialized, not
// ready and not healthy.
// While its previous call has not returned, it is not called again and the
// timeout is reported again.
func (m *Manager) checkWithTimeout(ctx context.Context, st *checkerState) CheckerStatus {
	if !st.inFlight.CompareAndSwap(false, true) {
		return st.timedOut()
	}
	checkCtx, cancel := context.WithTimeout(ctx, m.CheckTimeout)
	defer cancel()

	done := make(chan CheckerStatus, 1)
	go func() {
		status := st.check(checkCtx)
		st.inFlight.Store(false)
		done <- status
	}()

	select {
	case status := <-done:
		return status
	case <-checkCtx.Done():
		log.Ctx(ctx).Warn().
			Str("service-id", string(st.Service())).
			Str("component", st.Component()).
			Msg("health check timed out")
		return st.timedOut()
	}
}

func (st *checkerState) check(ctx context.Context) CheckerStatus {
	initialized := newCondition(st.Initialized(ctx))
	ready := initialized
	if initialized.OK {
		ready = newCondition(st.Ready(ctx))
	}
	return CheckerStatus{
		Service:     st.Service(),
		Name:        st.Component(),
		Initialized: initialized,
		Ready:       ready,
		Healthy:     newCondition(st.Healthy(ctx)),
	}
}

func newCondition(ok bool, info Info) Condition {
	info.Details = maps.Clone(info.Details)
	return Condition{OK: ok, Info: info}
}

func (st *checkerState) timedOut() CheckerStatus {
	failed := Condition{Info: Info{
		Reason: fmt.Sprintf("health check %s/%s timed out", st.Service(), st.Component()),
	}}
	return CheckerStatus{Service: st.Service(), Name: st.Component(), Initialized: failed, Ready: failed, Healthy: failed}
}

func (m *Manager) buildSnapshotLocked() Snapshot {
	var snap Snapshot
	for _, st := range m.checkers {
		snap.Checkers = append(snap.Checkers, st.last)
	}
	slices.SortFunc(snap.Checkers, func(a, b CheckerStatus) int {
		return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(a.Name, b.Name))
	})
	return snap
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
