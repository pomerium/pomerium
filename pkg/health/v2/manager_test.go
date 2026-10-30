package healthv2

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
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
				m.RegisterChecker(newChecker(check.GroupProxy, "proxy", running("proxy.service")))
				m.RegisterChecker(newChecker(check.GroupControlPlane, "xds", running("xds.cluster")))
			},
			want: []CheckerStatus{
				checkerStatus(check.GroupControlPlane, "xds", running("xds.cluster")),
				checkerStatus(check.GroupProxy, "proxy", running("proxy.service")),
			},
		},
		{
			name: "replace by group and name",
			setup: func(m *Manager) {
				m.RegisterChecker(newChecker(check.GroupProxy, "proxy", running("old")))
				m.RegisterChecker(newChecker(check.GroupProxy, "proxy", running("new")))
			},
			want: []CheckerStatus{
				checkerStatus(check.GroupProxy, "proxy", running("new")),
			},
		},
		{
			name: "same name in different groups",
			setup: func(m *Manager) {
				m.RegisterChecker(newChecker(check.GroupProxy, "svc", running("proxy.service")))
				m.RegisterChecker(newChecker(check.GroupAuthorize, "svc", running("authorize.service")))
			},
			want: []CheckerStatus{
				checkerStatus(check.GroupAuthorize, "svc", running("authorize.service")),
				checkerStatus(check.GroupProxy, "svc", running("proxy.service")),
			},
		},
		{
			name: "expected check not returned is unknown",
			setup: func(m *Manager) {
				c := newChecker(check.GroupDataBroker, "storage", running("storage.backend"))
				c.expected = append(c.expected, "storage.backend.cleanup")
				m.RegisterChecker(c)
			},
			want: []CheckerStatus{
				checkerStatus(check.GroupDataBroker, "storage", running("storage.backend"), check.Result{Name: "storage.backend.cleanup"}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestManager()
			m.ConfigureChecks(&config.Options{})
			tc.setup(m)
			m.poll(t.Context())
			assert.Equal(t, Snapshot{Configured: true, Checkers: tc.want}, m.Snapshot())
		})
	}
}

func TestManagerConfigureChecks(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	proxy := newChecker(check.GroupProxy, "proxy", running("proxy.service"))
	proxy.enabled = func(o *config.Options) bool { return config.IsProxy(o.Services) }
	authorize := newChecker(check.GroupAuthorize, "authorize", running("authorize.service"))
	authorize.enabled = func(o *config.Options) bool { return config.IsAuthorize(o.Services) }
	m.RegisterChecker(proxy)
	m.RegisterChecker(authorize)

	t.Run("nothing enabled before configure", func(t *testing.T) {
		m.poll(t.Context())
		assert.Equal(t, Snapshot{}, m.Snapshot())
		assert.False(t, m.Snapshot().Ready())
	})
	t.Run("enabled checkers only", func(t *testing.T) {
		m.ConfigureChecks(&config.Options{Services: config.ServiceProxy})
		m.poll(t.Context())
		assert.Equal(t, Snapshot{Configured: true, Checkers: []CheckerStatus{
			checkerStatus(check.GroupProxy, "proxy", running("proxy.service")),
		}}, m.Snapshot())
	})
	t.Run("disabled checker drops out", func(t *testing.T) {
		m.ConfigureChecks(&config.Options{Services: config.ServiceAuthorize})
		m.poll(t.Context())
		assert.Equal(t, Snapshot{Configured: true, Checkers: []CheckerStatus{
			checkerStatus(check.GroupAuthorize, "authorize", running("authorize.service")),
		}}, m.Snapshot())
	})
	t.Run("checker registered later uses current config", func(t *testing.T) {
		late := newChecker(check.GroupAuthorize, "late", running("late"))
		late.enabled = func(o *config.Options) bool { return config.IsAuthorize(o.Services) }
		m.RegisterChecker(late)
		m.poll(t.Context())
		assert.Equal(t, []string{"authorize.service", "late"}, m.Snapshot().Required())
	})
}

func TestManagerReportsLeafNamesOnly(t *testing.T) {
	t.Parallel()

	t.Run("first check times out", func(t *testing.T) {
		t.Parallel()
		m := newTestManager()
		m.ConfigureChecks(&config.Options{})
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		c := newChecker(check.GroupControlPlane, "xds", running("xds.cluster"), running("xds.listener"))
		c.checkFn = func(context.Context) []check.Result {
			<-block
			return nil
		}
		m.RegisterChecker(c)
		m.poll(t.Context())

		assert.Equal(t, []string{"xds.cluster", "xds.listener"}, m.Snapshot().Required())
		for _, r := range m.Snapshot().Checkers[0].Results {
			assert.Equal(t, check.StatusUnknown, r.Status, r.Name)
			assert.EqualError(t, r.Err, "health check ControlPlane/xds timed out", r.Name)
		}
	})
	t.Run("registered during a poll", func(t *testing.T) {
		t.Parallel()
		m := newTestManager()
		m.ConfigureChecks(&config.Options{})
		late := newChecker(check.GroupControlPlane, "xds", running("xds.cluster"))
		first := newChecker(check.GroupProxy, "proxy", running("proxy.service"))
		first.checkFn = func(context.Context) []check.Result {
			m.RegisterChecker(late)
			return []check.Result{running("proxy.service")}
		}
		m.RegisterChecker(first)
		m.poll(t.Context())

		assert.Equal(t, Snapshot{Configured: true, Checkers: []CheckerStatus{
			checkerStatus(check.GroupControlPlane, "xds", check.Result{Name: "xds.cluster"}),
			checkerStatus(check.GroupProxy, "proxy", running("proxy.service")),
		}}, m.Snapshot())
		assert.False(t, m.Snapshot().Started())
	})
}

func TestManagerCallsCheckOncePerPoll(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	m.ConfigureChecks(&config.Options{})
	c := newChecker(check.GroupProxy, "proxy", running("proxy.service"))
	m.RegisterChecker(c)
	m.poll(t.Context())
	assert.Equal(t, int32(1), c.calls.Load())
}

func TestManagerNotifiesOnChangeOnly(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	m.ConfigureChecks(&config.Options{})
	c := newChecker(check.GroupProxy, "proxy", running("proxy.service"))
	m.RegisterChecker(c)
	sink := &recordingSink{}
	m.RegisterSink(sink)

	m.poll(t.Context())
	assert.Equal(t, 1, sink.count())
	m.poll(t.Context())
	assert.Equal(t, 1, sink.count())

	c.set(failing("proxy.service", check.StatusRunning, "boom"))
	m.poll(t.Context())
	assert.Equal(t, 2, sink.count())
}

func TestManagerCloseClosesSinks(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	sinks := []*recordingSink{{}, {}}
	for _, s := range sinks {
		m.RegisterSink(s)
	}
	m.Close()
	for _, s := range sinks {
		assert.True(t, s.closed)
	}
}

func TestManagerCheckTimeout(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	m.ConfigureChecks(&config.Options{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	slow := newChecker(check.GroupDataBroker, "slow", running("databroker.slow"))
	slow.checkFn = func(context.Context) []check.Result {
		<-release
		return nil
	}
	m.RegisterChecker(slow)
	m.RegisterChecker(newChecker(check.GroupProxy, "fast", running("proxy.service")))

	wantErr := "health check DataBroker/slow timed out"
	for i := range 3 {
		start := time.Now()
		m.poll(t.Context())
		assert.Less(t, time.Since(start), time.Second, "poll %d is bounded by the check timeout", i)

		snap := m.Snapshot()
		require.Len(t, snap.Checkers, 2)
		slowStatus, fastStatus := snap.Checkers[0], snap.Checkers[1]
		require.Len(t, slowStatus.Results, 1)
		assert.Equal(t, check.CheckName("databroker.slow"), slowStatus.Results[0].Name)
		assert.EqualError(t, slowStatus.Results[0].Err, wantErr)
		assert.False(t, snap.Ready())
		assert.Equal(t, checkerStatus(check.GroupProxy, "fast", running("proxy.service")), fastStatus)
	}
	assert.Equal(t, int32(1), slow.calls.Load(), "no second call while the first is in flight")
}

func TestManagerTimeoutKeepsLeafNames(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	m.ConfigureChecks(&config.Options{})
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	c := newChecker(check.GroupControlPlane, "xds", running("xds.cluster"), running("xds.listener"))
	m.RegisterChecker(c)
	m.poll(t.Context())

	c.checkFn = func(context.Context) []check.Result {
		<-block
		return nil
	}
	m.poll(t.Context())

	results := m.Snapshot().Checkers[0].Results
	require.Len(t, results, 2)
	for i, name := range []check.CheckName{"xds.cluster", "xds.listener"} {
		assert.Equal(t, name, results[i].Name)
		assert.Equal(t, check.StatusRunning, results[i].Status)
		assert.Error(t, results[i].Err)
	}
}

func TestManagerShutdownIsNotLoggedAsTimeout(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	m := NewManager(Options{CheckTimeout: time.Minute})
	m.ConfigureChecks(&config.Options{})
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c := newChecker(check.GroupProxy, "proxy", running("proxy.service"))
	c.checkFn = func(context.Context) []check.Result {
		close(started)
		<-release
		return nil
	}
	m.RegisterChecker(c)

	ctx, cancel := context.WithCancel(zerolog.New(&buf).WithContext(t.Context()))
	done := make(chan struct{})
	go func() {
		m.poll(ctx)
		close(done)
	}()
	<-started
	cancel()
	<-done
	assert.Empty(t, buf.String())
}

func TestManagerStickyTerminating(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	m.ConfigureChecks(&config.Options{})
	m.RegisterChecker(newChecker(check.GroupProxy, "proxy",
		running("proxy.service"),
		failing("proxy.other", check.StatusRunning, "boom"),
	))
	sink := &recordingSink{}
	m.RegisterSink(sink)

	ctx, cancel := context.WithCancel(t.Context())
	errC := make(chan error, 1)
	go func() { errC <- m.Run(ctx) }()
	require.Eventually(t, func() bool { return m.Snapshot().Started() }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-errC, context.Canceled)

	assertTerminating := func(t *testing.T, snap Snapshot) {
		t.Helper()
		assert.True(t, snap.Terminating)
		assert.False(t, snap.Ready())
		assert.True(t, snap.AllTerminating())
	}
	assertTerminating(t, m.Snapshot())
	sink.mu.Lock()
	assertTerminating(t, sink.snaps[len(sink.snaps)-1])
	sink.mu.Unlock()

	m.poll(t.Context())
	assertTerminating(t, m.Snapshot())
}

func TestManagerLastPollAdvancesAfterFullPoll(t *testing.T) {
	t.Parallel()

	m := NewManager(Options{CheckTimeout: time.Minute})
	m.ConfigureChecks(&config.Options{})
	release := make(chan struct{})
	c := newChecker(check.GroupProxy, "proxy", running("proxy.service"))
	c.checkFn = func(context.Context) []check.Result {
		<-release
		return []check.Result{running("proxy.service")}
	}
	m.RegisterChecker(c)

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

func TestManagerConcurrentConfigureAndPoll(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	c := newChecker(check.GroupProxy, "proxy", running("proxy.service"))
	c.enabled = func(o *config.Options) bool { return config.IsProxy(o.Services) }
	m.RegisterChecker(c)
	m.RegisterSink(&recordingSink{})

	ctx, cancel := context.WithCancel(t.Context())
	errC := make(chan error, 1)
	go func() { errC <- m.Run(ctx) }()

	for i := range 200 {
		services := config.ServiceProxy
		if i%2 == 0 {
			services = config.ServiceAll
		}
		m.ConfigureChecks(&config.Options{Services: services})
		c.set(running("proxy.service"), running("proxy.extra"))
		_ = m.Snapshot().Ready()
		if i%10 == 0 {
			m.RegisterChecker(newChecker(check.GroupAuthorize, "authorize", running("authorize.service")))
		}
	}
	require.Eventually(t, func() bool { return m.Snapshot().Ready() }, time.Second, time.Millisecond)
	cancel()
	assert.ErrorIs(t, <-errC, context.Canceled)
}
