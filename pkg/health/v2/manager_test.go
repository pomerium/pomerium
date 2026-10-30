package healthv2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManager() *Manager {
	return NewManager(Options{PollInterval: time.Millisecond, CheckTimeout: 50 * time.Millisecond})
}

func TestManagerRegistry(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		setup func(m *Manager)
		want  []CheckerStatus
	}{
		{
			name: "register",
			setup: func(m *Manager) {
				m.RegisterHealthChecker(newChecker(ServiceProxy, "proxy"))
				m.RegisterHealthChecker(newChecker(ServiceControlPlane, "xds"))
			},
			want: []CheckerStatus{
				running(ServiceControlPlane, "xds"),
				running(ServiceProxy, "proxy"),
			},
		},
		{
			name: "replace",
			setup: func(m *Manager) {
				m.RegisterHealthChecker(newChecker(ServiceProxy, "proxy"))
				replacement := newChecker(ServiceProxy, "proxy")
				replacement.set(fail("new"), pass(nil))
				m.RegisterHealthChecker(replacement)
			},
			want: []CheckerStatus{
				checkerStatus(ServiceProxy, "proxy", fail("new"), pass(nil)),
			},
		},
		{
			name: "groups",
			setup: func(m *Manager) {
				m.RegisterHealthChecker(newChecker(ServiceProxy, "svc"))
				m.RegisterHealthChecker(newChecker(ServiceAuthorize, "svc"))
			},
			want: []CheckerStatus{
				running(ServiceAuthorize, "svc"),
				running(ServiceProxy, "svc"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestManager()
			tc.setup(m)
			m.poll(t.Context())
			assert.Equal(t, Snapshot{Checkers: tc.want}, m.Snapshot())
		})
	}
}

func TestManagerCallsCheckOncePerPoll(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	c := newChecker(ServiceProxy, "proxy")
	m.RegisterHealthChecker(c)
	m.poll(t.Context())
	assert.Equal(t, int32(1), c.calls.Load())
}

func TestManagerUninitialized(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	c := newChecker(ServiceProxy, "proxy")
	c.setInitialized(Condition{Info: Info{Reason: "loading", Details: map[string]string{"k": "v"}}})
	m.RegisterHealthChecker(c)

	m.poll(t.Context())
	snap := m.Snapshot()
	loading := Condition{Info: Info{Reason: "loading", Details: map[string]string{"k": "v"}}}
	assert.Equal(t, []CheckerStatus{
		{Service: ServiceProxy, Name: "proxy", Initialized: loading, Ready: loading, Healthy: pass(nil)},
	}, snap.Checkers)
	assert.Zero(t, c.calls.Load(), "ready is not called before initialized")
	assert.False(t, snap.Initialized())
	assert.False(t, snap.Ready())
	assert.True(t, snap.Healthy())

	c.setInitialized(pass(nil))
	m.poll(t.Context())
	assert.Equal(t, []CheckerStatus{running(ServiceProxy, "proxy")}, m.Snapshot().Checkers)
	assert.Equal(t, int32(1), c.calls.Load())
}

func TestManagerNotifiesOnChangeOnly(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	c := newChecker(ServiceProxy, "proxy")
	m.RegisterHealthChecker(c)
	sink := &recordingSink{}
	m.RegisterSink(sink)

	for _, step := range []struct {
		name             string
		ready, healthy   Condition
		wantNotification int
	}{
		{"initial", pass(nil), pass(nil), 1},
		{"unchanged", pass(nil), pass(nil), 1},
		{"reason_change", pass(nil), fail("boom"), 2},
		{"details_change", pass(map[string]string{"role": "follower"}), fail("boom"), 3},
		{"details_unchanged", pass(map[string]string{"role": "follower"}), fail("boom"), 3},
	} {
		c.set(step.ready, step.healthy)
		m.poll(t.Context())
		assert.Equal(t, step.wantNotification, sink.count(), step.name)
	}
}

func TestManagerSinkLifecycle(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	sinks := []*recordingSink{{}, {}}
	for _, s := range sinks {
		m.RegisterSink(s)
	}
	for _, s := range sinks {
		assert.False(t, s.started)
	}

	go m.Run(t.Context())
	for _, s := range sinks {
		assert.Eventually(t, func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.started
		}, time.Second, time.Millisecond)
	}
}

func TestManagerCheckTimeout(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	slow := newChecker(ServiceDataBroker, "slow")
	slow.readyFn = func(context.Context) { <-release }
	m.RegisterHealthChecker(slow)
	m.RegisterHealthChecker(newChecker(ServiceProxy, "fast"))

	timedOut := fail("health check DataBroker/slow timed out")
	for i := range 3 {
		start := time.Now()
		m.poll(t.Context())
		assert.Less(t, time.Since(start), time.Second, "poll %d is bounded by the check timeout", i)

		snap := m.Snapshot()
		assert.Equal(t, []CheckerStatus{
			{Service: ServiceDataBroker, Name: "slow", Initialized: timedOut, Ready: timedOut, Healthy: timedOut},
			running(ServiceProxy, "fast"),
		}, snap.Checkers)
		assert.False(t, snap.Ready())
		assert.False(t, snap.Healthy())
	}
	assert.Equal(t, int32(1), slow.calls.Load(), "no second call while the first is in flight")
}

func TestManagerPollsAfterShutdown(t *testing.T) {
	t.Parallel()

	m := NewManager(Options{PollInterval: 10 * time.Millisecond, CheckTimeout: 50 * time.Millisecond})
	c := newChecker(ServiceEnvoy, "drain")
	m.RegisterHealthChecker(c)
	sink := &recordingSink{}
	m.RegisterSink(sink)

	ctx, cancel := context.WithCancel(t.Context())
	go m.Run(ctx)
	require.Eventually(t, func() bool { return m.Snapshot().Ready() }, time.Second, time.Millisecond)
	cancel()

	for _, step := range []struct {
		name           string
		ready, healthy Condition
	}{
		{"draining", pass(nil), pass(nil)},
		{"drained", fail("drained"), pass(nil)},
		{"drain_failing", fail("drained"), fail("boom")},
	} {
		c.set(step.ready, step.healthy)
		require.Eventually(t, func() bool {
			snap := m.Snapshot()
			return snap.Ready() == step.ready.OK && snap.Healthy() == step.healthy.OK
		}, time.Second, time.Millisecond, step.name)
	}
	require.Eventually(t, func() bool { return !sink.last().Healthy() }, time.Second, time.Millisecond)
}

func TestManagerLastPollAdvancesAfterFullPoll(t *testing.T) {
	t.Parallel()

	m := NewManager(Options{CheckTimeout: time.Minute})
	release := make(chan struct{})
	c := newChecker(ServiceProxy, "proxy")
	c.readyFn = func(context.Context) { <-release }
	m.RegisterHealthChecker(c)

	done := make(chan struct{})
	go func() {
		m.poll(t.Context())
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	assert.True(t, m.LastPoll().IsZero())

	before := time.Now()
	close(release)
	<-done
	assert.False(t, m.LastPoll().Before(before))
}
