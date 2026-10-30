//go:build linux

package sink

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

type fakeProgress func() time.Time

func (f fakeProgress) LastPoll() time.Time { return f() }

func listenNotifySocket(t *testing.T) (string, *net.UnixConn) {
	t.Helper()
	addr := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: addr, Net: "unixgram"})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return addr, conn
}

func readNotify(t *testing.T, conn *net.UnixConn, timeout time.Duration) (string, error) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(timeout)))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func awaitNotify(t *testing.T, conn *net.UnixConn, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		msg, err := readNotify(t, conn, time.Until(deadline))
		require.NoError(t, err, "waiting for %s", want)
		if msg == want {
			return
		}
	}
}

func TestSystemdNotifications(t *testing.T) {
	t.Parallel()

	addr, conn := listenNotifySocket(t)
	sink, err := NewSystemd(fakeProgress(time.Now), SystemdOptions{Addr: addr})
	require.NoError(t, err)
	sink.Run()
	shutdownCtx, cancel := context.WithCancel(t.Context())
	cancel()

	for _, step := range []struct {
		name   string
		snap   healthv2.Snapshot
		action func()
		want   string
	}{
		{name: "no_reason", snap: snapshotOf(running("a"), uninitialized(running("b"), ""))},
		{name: "reason", snap: snapshotOf(running("a"), uninitialized(running("b"), "some error")), want: "STATUS=Proxy/b: some error"},
		{name: "same_reason", snap: snapshotOf(running("a"), uninitialized(running("b"), "some error"))},
		{name: "reason_change", snap: snapshotOf(running("a"), uninitialized(running("b"), "other error")), want: "STATUS=Proxy/b: other error"},
		{name: "truncated", snap: snapshotOf(running("a"), uninitialized(running("b"), strings.Repeat("x", 100))), want: "STATUS=Proxy/b: " + strings.Repeat("x", 64) + "..."},
		{name: "initialized", snap: snapshotOf(running("a"), checkerStatus("b", fail(""), pass(nil))), want: "READY=1"},
		{name: "ready_once", snap: snapshotOf(running("a"), running("b"))},
		{name: "not_ready_reason", snap: snapshotOf(running("a"), checkerStatus("b", fail("syncing"), pass(nil))), want: "STATUS=Proxy/b: syncing"},
		{name: "stopping", action: func() { sink.Shutdown(shutdownCtx) }, want: "STOPPING=1"},
		{name: "stopping_once", action: func() { sink.Shutdown(shutdownCtx) }},
	} {
		t.Run(step.name, func(t *testing.T) {
			if step.action != nil {
				step.action()
			} else {
				sink.Notify(step.snap)
			}
			msg, err := readNotify(t, conn, 200*time.Millisecond)
			if step.want == "" {
				assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, step.want, msg)
		})
	}
}

func TestSystemdWatchdog(t *testing.T) {
	t.Parallel()

	const interval = 50 * time.Millisecond
	for _, tc := range []struct {
		name          string
		progress      fakeProgress
		start         bool
		wantHeartbeat bool
	}{
		{"polls completing", time.Now, true, true},
		{"not started", time.Now, false, false},
		{"poll loop stalled", func() time.Time { return time.Now().Add(-time.Hour) }, true, false},
		{"never polled", func() time.Time { return time.Time{} }, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, conn := listenNotifySocket(t)
			sink, err := NewSystemd(tc.progress, SystemdOptions{Addr: addr, WatchdogInterval: interval})
			require.NoError(t, err)
			if tc.start {
				sink.Run()
			}

			if !tc.wantHeartbeat {
				_, err := readNotify(t, conn, 4*interval)
				assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
				return
			}
			for range 3 {
				msg, err := readNotify(t, conn, 4*interval)
				require.NoError(t, err)
				assert.Equal(t, "WATCHDOG=1", msg)
			}
		})
	}
}

func TestSystemdWatchdogContinuesAfterShutdown(t *testing.T) {
	t.Parallel()

	const interval = 50 * time.Millisecond
	addr, conn := listenNotifySocket(t)
	m := healthv2.NewManager(healthv2.Options{PollInterval: time.Millisecond})
	m.RegisterHealthChecker(newChecker("a"))
	sink, err := NewSystemd(m, SystemdOptions{Addr: addr, WatchdogInterval: interval})
	require.NoError(t, err)
	m.RegisterSink(sink)
	shutdownCtx, shutdown := context.WithCancel(t.Context())
	context.AfterFunc(shutdownCtx, func() { sink.Shutdown(shutdownCtx) })

	runManager(t, m)
	awaitNotify(t, conn, "WATCHDOG=1", 4*interval)

	shutdown()
	awaitNotify(t, conn, "STOPPING=1", 4*interval)
	time.Sleep(2 * interval)
	for {
		if _, err := readNotify(t, conn, time.Millisecond); err != nil {
			break
		}
	}
	awaitNotify(t, conn, "WATCHDOG=1", 4*interval)
}

type fakeNotifyConn struct {
	mu       sync.Mutex
	failOn   string
	failures int
	msgs     []string
}

func (c *fakeNotifyConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, string(b))
	if string(b) == c.failOn && c.failures > 0 {
		c.failures--
		return 0, errors.New("write failed")
	}
	return len(b), nil
}

func (c *fakeNotifyConn) Close() error { return nil }

func (c *fakeNotifyConn) sent() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.msgs)
}

func TestSystemdShutdownSendsStopping(t *testing.T) {
	t.Parallel()

	shutdownCtx, cancel := context.WithCancel(t.Context())
	cancel()

	t.Run("sent", func(t *testing.T) {
		t.Parallel()
		conn := &fakeNotifyConn{}
		sink := newSystemd(conn, fakeProgress(time.Now), SystemdOptions{})
		sink.Shutdown(shutdownCtx)
		assert.Equal(t, []string{"STOPPING=1"}, conn.sent())
	})
	t.Run("retry", func(t *testing.T) {
		t.Parallel()
		conn := &fakeNotifyConn{failOn: "STOPPING=1", failures: 1}
		sink := newSystemd(conn, fakeProgress(time.Now), SystemdOptions{})
		sink.Shutdown(shutdownCtx)
		assert.Equal(t, []string{"STOPPING=1", "STOPPING=1"}, conn.sent())
		assert.Zero(t, conn.failures)
	})
}

func TestSystemdReadyRetryDoesNotBlockUpdates(t *testing.T) {
	t.Parallel()

	conn := &fakeNotifyConn{failOn: "READY=1", failures: math.MaxInt}
	sink := newSystemd(conn, fakeProgress(time.Now), SystemdOptions{})
	sink.Run()
	shutdownCtx, cancel := context.WithCancel(t.Context())
	cancel()

	for _, step := range []struct {
		do   func()
		want string
	}{
		{func() { sink.Notify(snapshotOf(running("a"))) }, "READY=1"},
		{func() { sink.Notify(snapshotOf(checkerStatus("a", pass(nil), fail("boom")))) }, "STATUS=Proxy/a: boom"},
		{func() { sink.Shutdown(shutdownCtx) }, "STOPPING=1"},
	} {
		step.do()
		assert.Eventually(t, func() bool {
			return slices.Contains(conn.sent(), step.want)
		}, 500*time.Millisecond, time.Millisecond, step.want)
	}
}
