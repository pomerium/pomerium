package health

import (
	"fmt"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

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
	synctest.Run(func() {
		start := time.Now()
		serveConn.SetReadDeadline(time.Now().Add(3 * watchConf.Interval))
		go func() {
			time.Sleep(2 * watchConf.Interval)
		}()
		synctest.Wait()
		b := make([]byte, 100)
		oob := make([]byte, 1000)
		n, oobN, _, _, err := serveConn.ReadMsgUnix(b, oob)
		assert.NoError(err)
		assert.Equal(0, oobN)
		assert.Equal(10, n)
		assert.Equal("WATCHDOG=1", string(b[:n]))
		t.Logf("%v", time.Since(start))
		synctest.Wait()
		n, oobN, _, _, err = serveConn.ReadMsgUnix(b, oob)
		assert.NoError(err)
		assert.Equal(0, oobN)
		assert.Equal(10, n)
		assert.Equal("WATCHDOG=1", string(b[:n]))
		t.Logf("%v", time.Since(start))
		synctest.Wait()
		n, oobN, _, _, err = serveConn.ReadMsgUnix(b, oob)
		assert.NoError(err)
		assert.Equal(0, oobN)
		assert.Equal(10, n)
		assert.Equal("WATCHDOG=1", string(b[:n]))
		t.Logf("%v", time.Since(start))
		synctest.Wait()
		n, oobN, _, _, err = serveConn.ReadMsgUnix(b, oob)
		assert.NoError(err)
		assert.Equal(0, oobN)
		assert.Equal(10, n)
		assert.Equal("WATCHDOG=1", string(b[:n]))
		t.Logf("%v", time.Since(start))
		synctest.Wait()
		sysd.Shutdown()
		synctest.Wait()
		t.Logf("%v", time.Since(start))
		n, oobN, _, _, err = serveConn.ReadMsgUnix(b, oob)
		assert.Equal(0, oobN)
		assert.Equal(-1, n)
		assert.ErrorIs(err, os.ErrDeadlineExceeded)
	})
}
