//go:build linux

package health

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemdOverloadDoesNotBlockStartup(t *testing.T) {
	sock := t.TempDir() + "/notify.sock"
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	mgr := NewManager()
	checks := WithExpectedChecks(EnvoyServer, EnvoyOverload, BlobStorage, RecordingHandler)
	sysd, err := NewSystemDProvider(t.Context(), mgr, sock, SystemdWatchdogConf{}, checks)
	require.NoError(t, err)
	t.Cleanup(func() {
		sysd.Shutdown()
		_ = sysd.conn.Close()
	})
	mgr.Register(ProviderSystemd, sysd)

	mgr.ReportError(EnvoyOverload, errors.New("envoy overloaded"))
	mgr.ReportStatus(EnvoyServer, StatusRunning)
	assert.False(t, sysd.isStarted(), "recording checks must still block startup")
	mgr.ReportStatus(BlobStorage, StatusRunning)
	assert.False(t, sysd.isStarted(), "recording handler must still block startup")
	mgr.ReportStatus(RecordingHandler, StatusRunning)
	assert.True(t, sysd.isStarted())

	require.NoError(t, listener.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 256)
	for {
		n, _, err := listener.ReadFromUnix(buf)
		require.NoError(t, err, "systemd must receive READY=1 despite overload")
		if string(buf[:n]) == sdNotifyReady {
			break
		}
	}

	httpProvider := NewHTTPProvider(mgr, checks)
	for _, probe := range []struct {
		handler http.HandlerFunc
		code    int
	}{
		{httpProvider.ReadyProbe, http.StatusServiceUnavailable},
		{httpProvider.StartupProbe, http.StatusOK},
		{httpProvider.LivenessProbe, http.StatusOK},
	} {
		rec := httptest.NewRecorder()
		probe.handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, probe.code, rec.Code, rec.Body.String())
	}
}

func TestSystemdProvider(t *testing.T) {
	assert := assert.New(t)
	c1, c2, c3 := Check("a"), Check("b"), Check("c")
	sockDir := t.TempDir()

	sock := sockDir + "/notify-socket.sock"
	laddr := net.UnixAddr{
		Name: sock,
		Net:  "unixgram",
	}
	serveConn, err := net.ListenUnixgram("unixgram", &laddr)
	assert.NoError(err)
	mgr := NewManager()
	sysd, err := NewSystemDProvider(t.Context(), mgr, sock, SystemdWatchdogConf{
		Enabled:  false,
		Interval: 0,
	}, WithExpectedChecks(
		c1,
		c2,
		c3,
	))
	assert.NoError(err)
	mgr.Register(ProviderSystemd, sysd)
	mgr.ReportStatus(c1, StatusRunning)
	b1 := []byte{}
	oob := []byte{}
	serveConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, oobN, _, _, err := serveConn.ReadMsgUnix(b1, oob)
	assert.ErrorIs(err, os.ErrDeadlineExceeded)
	assert.Equal(-1, n)
	assert.Equal(0, oobN)
	mgr.ReportError(c2, fmt.Errorf("some error"))
	serveConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	b2 := make([]byte, 100)
	n, oobN, _, _, err = serveConn.ReadMsgUnix(b2, oob)
	assert.NoError(err)
	assert.Equal(0, oobN)
	assert.Equal(29, n)
	assert.Equal("STATUS=Error in b: some error", string(b2[:n]))

	mgr.ReportError(c3, fmt.Errorf("some newer error"))
	n, oobN, _, _, err = serveConn.ReadMsgUnix(b2, oob)
	assert.NoError(err)
	assert.Equal(0, oobN)
	assert.Equal(35, n)
	assert.Equal("STATUS=Error in c: some newer error", string(b2[:n]))

	mgr.ReportStatus(c2, StatusRunning)
	mgr.ReportStatus(c3, StatusRunning)
	b3 := make([]byte, 100)
	n, oobN, _, _, err = serveConn.ReadMsgUnix(b3, oob)
	assert.NoError(err)
	assert.Equal(0, oobN)
	assert.Equal(7, n)
	assert.Equal("READY=1", string(b3[:n]))

	mgr.ReportStatus(c1, StatusTerminating)
	b4 := make([]byte, 100)
	n, oobN, _, _, err = serveConn.ReadMsgUnix(b4, oob)
	assert.NoError(err)
	assert.Equal(0, oobN)
	assert.Equal(10, n)
	assert.Equal("STOPPING=1", string(b4[:n]))
}

func TestSystemdWatchDog(t *testing.T) {
	assert := assert.New(t)
	sockDir := t.TempDir()
	sock := sockDir + "/notify-socket.sock"
	laddr := net.UnixAddr{
		Name: sock,
		Net:  "unixgram",
	}
	serveConn, err := net.ListenUnixgram("unixgram", &laddr)
	assert.NoError(err)
	mgr := NewManager()
	watchConf := SystemdWatchdogConf{
		Enabled:  true,
		Interval: time.Millisecond * 50,
	}
	sysd, err := NewSystemDProvider(t.Context(), mgr, sock, watchConf)
	assert.NoError(err)
	sysd.Start()
	serveConn.SetReadDeadline(time.Now().Add(4 * watchConf.Interval))
	go func() {
		time.Sleep(2 * watchConf.Interval)
	}()
	b := make([]byte, 100)
	oob := make([]byte, 1000)

	for range 4 {
		n, oobN, _, _, err := serveConn.ReadMsgUnix(b, oob)
		assert.NoError(err)
		assert.Equal(0, oobN)
		assert.Equal(10, n)
		assert.Equal("WATCHDOG=1", string(b[:n]))
	}
	sysd.Shutdown()

	// hack: synctest doesn't play nice with tickers.
	// read an extra message if it was sent, due to race condition
	n, oobN, _, _, err := serveConn.ReadMsgUnix(b, oob)
	if err != nil {
		_, _, _, _, err := serveConn.ReadMsgUnix(b, oob)
		assert.ErrorIs(err, os.ErrDeadlineExceeded)
		return
	}
	assert.NoError(err)
	assert.Equal(0, oobN)
	assert.Equal(10, n)
	assert.Equal("WATCHDOG=1", string(b[:n]))

	n, oobN, _, _, err = serveConn.ReadMsgUnix(b, oob)
	assert.Equal(0, oobN)
	assert.Equal(-1, n)
	assert.ErrorIs(err, os.ErrDeadlineExceeded)
}
