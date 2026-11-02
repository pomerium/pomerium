//go:build linux

package sink

import (
	"errors"
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

	"github.com/pomerium/pomerium/config"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
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
	sink.Start()
	t.Cleanup(sink.Close)

	for _, step := range []struct {
		name string
		snap healthv2.Snapshot
		want string
	}{
		{"unknown sends nothing", snapshotOf(running("a"), check.Result{Name: "b"}), ""},
		{"error sets status", snapshotOf(running("a"), failing("b", check.StatusUnknown, "some error")), "STATUS=Error in b: some error"},
		{"same error is not resent", snapshotOf(running("a"), failing("b", check.StatusUnknown, "some error")), ""},
		{"long error is truncated", snapshotOf(running("a"), failing("b", check.StatusUnknown, strings.Repeat("x", 100))), "STATUS=Error in b: " + strings.Repeat("x", 61) + "..."},
		{"all running sends ready", snapshotOf(running("a"), running("b")), "READY=1"},
		{"ready is sent once", snapshotOf(running("a"), running("b", check.Attr{Key: "k", Value: "v"})), ""},
		{"terminating sends stopping", snapshotOf(terminating("a"), running("b")), "STOPPING=1"},
		{"stopping is sent once", snapshotOf(terminating("a"), terminating("b")), ""},
	} {
		sink.Notify(step.snap)
		msg, err := readNotify(t, conn, 200*time.Millisecond)
		if step.want == "" {
			assert.ErrorIs(t, err, os.ErrDeadlineExceeded, step.name)
			continue
		}
		require.NoError(t, err, step.name)
		assert.Equal(t, step.want, msg, step.name)
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
				sink.Start()
			}
			t.Cleanup(sink.Close)

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
	m.ConfigureChecks(&config.Options{})
	m.RegisterChecker(newChecker(running("a")))
	sink, err := NewSystemd(m, SystemdOptions{Addr: addr, WatchdogInterval: interval})
	require.NoError(t, err)
	t.Cleanup(sink.Close)
	m.RegisterSink(sink)

	stop := runManager(t, m)
	awaitNotify(t, conn, "WATCHDOG=1", 4*interval)

	stop()
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
	mu     sync.Mutex
	failOn string
	msgs   []string
}

func (c *fakeNotifyConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, string(b))
	if string(b) == c.failOn {
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

func TestSystemdSendsStoppingBeforeClose(t *testing.T) {
	t.Parallel()

	conn := &fakeNotifyConn{}
	sink := newSystemd(conn, fakeProgress(time.Now), SystemdOptions{})
	sink.Start()
	sink.Notify(snapshotOf(terminating("a")))
	sink.Close()
	assert.Contains(t, conn.sent(), "STOPPING=1")
}

func TestSystemdReadyRetryDoesNotBlockUpdates(t *testing.T) {
	t.Parallel()

	conn := &fakeNotifyConn{failOn: "READY=1"}
	sink := newSystemd(conn, fakeProgress(time.Now), SystemdOptions{})
	sink.Start()
	t.Cleanup(sink.Close)

	for _, step := range []struct {
		snap healthv2.Snapshot
		want string
	}{
		{snapshotOf(running("a")), "READY=1"},
		{snapshotOf(failing("a", check.StatusRunning, "boom")), "STATUS=Error in a: boom"},
		{snapshotOf(terminating("a")), "STOPPING=1"},
	} {
		sink.Notify(step.snap)
		assert.Eventually(t, func() bool {
			return slices.Contains(conn.sent(), step.want)
		}, 500*time.Millisecond, time.Millisecond, step.want)
	}
}
