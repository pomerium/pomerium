package netutil_test

import (
	"errors"
	"net"
	"net/netip"
	"path"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/pomerium/pomerium/pkg/netutil"
)

func testNormalAndVirtualListeners(t *testing.T, fn func(t *testing.T, httpListener net.Listener, grpcListener net.Listener, grpcListenerIsVirtual bool) (shouldCleanup bool)) {
	t.Run("normal listeners", func(t *testing.T) {
		mux := netutil.NewListenerMux(zerolog.New(zerolog.NewTestWriter(t)))
		httpListener, err := mux.Listen("tcp", "127.0.0.1:0", "http")
		require.NoError(t, err)
		grpcListener, err := mux.Listen("tcp", "127.0.0.1:0", "grpc")
		require.NoError(t, err)

		if fn(t, httpListener, grpcListener, false) {
			assert.NoError(t, httpListener.Close())
			assert.NoError(t, grpcListener.Close())
		}
	})
	t.Run("virtual grpc listener", func(t *testing.T) {
		mux := netutil.NewListenerMux(zerolog.New(zerolog.NewTestWriter(t)))
		httpListener, err := mux.Listen("tcp", "127.0.0.1:0", "http")
		require.NoError(t, err)
		grpcListener := mux.AddVirtualListener(httpListener.Addr(), "grpc")
		assert.Equal(t, httpListener.Addr(), grpcListener.Addr())

		if fn(t, httpListener, grpcListener, true) {
			assert.NoError(t, httpListener.Close())
			assert.NoError(t, grpcListener.Close())
		}
	})
}

func TestListenerMux(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, grpcListenerIsVirtual bool) (shouldCleanup bool) {
		acceptHTTPConnAndVerify := func(expectedData string) {
			t.Helper()
			timer := time.AfterFunc(1*time.Second, func() {
				t.Error("timed out waiting to accept http connection")
				httpListener.Close()
			})
			sc, err := httpListener.Accept()
			timer.Stop()
			require.NoError(t, err)
			data := make([]byte, len(expectedData))
			n, err := sc.Read(data[:])
			require.NoError(t, err)
			require.Equal(t, len(expectedData), n)
			require.Equal(t, expectedData, string(data[:]))
			require.NoError(t, sc.Close())
		}

		acceptGrpcConnAndVerify := func(expectedData string) {
			t.Helper()
			timer := time.AfterFunc(1*time.Second, func() {
				t.Error("timed out waiting to accept grpc connection")
				grpcListener.Close()
			})
			sc, err := grpcListener.Accept()
			timer.Stop()
			require.NoError(t, err)
			data := make([]byte, len(expectedData))
			n, err := sc.Read(data[:])
			require.NoError(t, err)
			require.Equal(t, len(expectedData), n)
			require.Equal(t, expectedData, string(data[:]))
			require.NoError(t, sc.Close())
		}

		dialHTTPNormal := func(data string) {
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)
			cc.Write([]byte(data))
		}

		dialGRPCNormal := func(data string) {
			cc, err := net.Dial(grpcListener.Addr().Network(), grpcListener.Addr().String())
			require.NoError(t, err)
			cc.Write([]byte(data))
		}

		dialHTTPWithInitialMetadata := func(metadata string, data string) {
			require.LessOrEqual(t, len(metadata), 255)
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)
			cc.Write(append(append(
				[]byte{0x37, 0x32, 0x36, 0x31, byte(len(metadata))},
				metadata...),
				data...))
		}

		dialGRPCWithInitialMetadata := func(metadata string, data string) {
			require.LessOrEqual(t, len(metadata), 255)
			cc, err := net.Dial(grpcListener.Addr().Network(), grpcListener.Addr().String())
			require.NoError(t, err)
			cc.Write(append(append(
				[]byte{0x37, 0x32, 0x36, 0x31, byte(len(metadata))},
				metadata...),
				data...))
		}

		go dialHTTPNormal("http traffic")
		acceptHTTPConnAndVerify("http traffic")

		go dialHTTPWithInitialMetadata("grpc", "http to grpc")
		acceptGrpcConnAndVerify("http to grpc")

		if !grpcListenerIsVirtual {
			go dialGRPCNormal("grpc traffic")
			acceptGrpcConnAndVerify("grpc traffic")

			go dialGRPCWithInitialMetadata("http", "grpc to http")
			acceptHTTPConnAndVerify("grpc to http")
		}

		return true
	})
}

func TestListenerMux_CloseOnRealAcceptErr(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
		httpErr := make(chan error)
		go func() {
			_, err := httpListener.Accept()
			httpErr <- err
		}()

		grpcErr := make(chan error)
		go func() {
			_, err := grpcListener.Accept()
			grpcErr <- err
		}()

		runtime.Gosched()

		select {
		case <-httpErr:
			t.Fail()
		default:
		}

		select {
		case <-grpcErr:
			t.Fail()
		default:
		}

		require.NoError(t, httpListener.Close())
		err := <-httpErr
		require.ErrorIs(t, err, net.ErrClosed)

		require.NoError(t, grpcListener.Close())
		err = <-grpcErr
		require.ErrorIs(t, err, net.ErrClosed)

		return false
	})
}

func TestListenerMux_CloseWhileWaitingForProxyListenerAccept(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
		{
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)

			n, err := cc.Write(append(append(
				[]byte{0x37, 0x32, 0x36, 0x31, byte(len("grpc"))},
				"grpc"...),
				"hello world"...))
			assert.Equal(t, 20, n)
			assert.NoError(t, err)
			// now the listener mux will be waiting for the proxy grpc listener to accept
			// a connection
			require.NoError(t, grpcListener.Close())
			// acceptLoop is guaranteed to exit before Close() returns, so the client
			// connection is in the process of being closed. It may take a short
			// amount of time for the socket to be closed on the client end.
			assertConnectionClosed(t, cc)
		}

		{
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)
			n, err := cc.Write([]byte("hello world"))
			assert.Equal(t, 11, n)
			assert.NoError(t, err)
			// same thing as above but routing to the normal listener
			require.NoError(t, httpListener.Close())
			assertConnectionClosed(t, cc)
		}

		return false
	})
}

func TestListenerMux_ReadUnknownListenerID(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, _ net.Listener, _ bool) (shouldCleanup bool) {
		for _, invalidID := range []string{
			"unknown",
			"",
			strings.Repeat("a", 255),
			"http\x00",
		} {
			t.Run("", func(t *testing.T) {
				cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
				require.NoError(t, err)

				cc.Write(append(append(
					[]byte{0x37, 0x32, 0x36, 0x31, byte(len(invalidID))},
					invalidID...),
					"hello world"...))
				cc.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) // this shouldn't be hit
				var b [1]byte
				n, err := cc.Read(b[:])
				assert.Equal(t, 0, n)
				require.ErrorContains(t, err, "connection reset by peer")
			})
		}

		return true
	})
}

func TestListenerMux_ReadIncompleteHeader(t *testing.T) {
	defaultRecvTimeout := netutil.InitialRecvTimeout
	netutil.InitialRecvTimeout = 250 * time.Millisecond
	t.Cleanup(func() {
		netutil.InitialRecvTimeout = defaultRecvTimeout
	})

	for _, mode := range []string{"timeout", "close"} {
		t.Run(mode, func(t *testing.T) {
			check := func(cc net.Conn, httpListener net.Listener, grpcListener net.Listener) bool {
				switch mode {
				case "timeout":
					assertConnectionClosed(t, cc)

					// cleanup
					return true
				case "close":
					assert.NoError(t, httpListener.Close())
					assertConnectionClosed(t, cc)

					// cleanup
					assert.NoError(t, grpcListener.Close())
					return false
				default:
					panic("unreachable")
				}
			}

			t.Run("incomplete magic", func(t *testing.T) {
				testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
					cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
					require.NoError(t, err)

					n, err := cc.Write([]byte{0x37})
					assert.Equal(t, 1, n)
					require.NoError(t, err)

					n, err = cc.Write([]byte{0x32})
					assert.Equal(t, 1, n)
					require.NoError(t, err)

					n, err = cc.Write([]byte{0x36})
					assert.Equal(t, 1, n)
					require.NoError(t, err)

					return check(cc, httpListener, grpcListener)
				})
			})

			t.Run("incomplete size", func(t *testing.T) {
				testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
					cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
					require.NoError(t, err)

					n, err := cc.Write([]byte{0x37, 0x32})
					assert.Equal(t, 2, n)
					require.NoError(t, err)

					n, err = cc.Write([]byte{0x36, 0x31})
					assert.Equal(t, 2, n)
					require.NoError(t, err)

					return check(cc, httpListener, grpcListener)
				})
			})

			t.Run("no payload", func(t *testing.T) {
				testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
					cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
					require.NoError(t, err)

					n, err := cc.Write([]byte{0x37, 0x32, 0x36})
					assert.Equal(t, 3, n)
					require.NoError(t, err)

					n, err = cc.Write([]byte{0x31, 0x02})
					assert.Equal(t, 2, n)
					require.NoError(t, err)

					return check(cc, httpListener, grpcListener)
				})
			})

			t.Run("incomplete payload", func(t *testing.T) {
				testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
					cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
					require.NoError(t, err)

					n, err := cc.Write([]byte{0x37, 0x32, 0x36})
					assert.Equal(t, 3, n)
					require.NoError(t, err)

					n, err = cc.Write([]byte{0x31, 0x02, 'h'})
					assert.Equal(t, 3, n)
					require.NoError(t, err)

					return check(cc, httpListener, grpcListener)
				})
			})
		})
	}
}

func TestListenerMux_ReadNonMatchingHeader(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, _ net.Listener, _ bool) (shouldCleanup bool) {
		{
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)

			cc.Write([]byte{'H'})

			sc, err := httpListener.Accept()
			require.NoError(t, err)
			var data [10]byte
			n, err := sc.Read(data[:])
			require.Equal(t, 1, n)
			require.NoError(t, err)
			assert.Equal(t, []byte{'H'}, data[:n])
			assert.NoError(t, sc.Close())
			assert.NoError(t, cc.Close())

		}

		{
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)

			cc.Write([]byte{0x37, 0x32, 0x36})
			time.Sleep(10 * time.Millisecond)
			cc.Write([]byte{0x1})

			sc, err := httpListener.Accept()
			require.NoError(t, err)
			var data [10]byte
			n, err := sc.Read(data[:])
			require.Equal(t, 4, n)
			require.NoError(t, err)
			assert.Equal(t, []byte{0x37, 0x32, 0x36, 0x1}, data[:n])
			assert.NoError(t, sc.Close())
			assert.NoError(t, cc.Close())
		}
		return true
	})
}

func TestListenerMux_NonBlocking(t *testing.T) {
	// test that if a client sends an incomplete header and we are waiting
	// for the remainder of it, new connections are not blocked.

	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
		_ = grpcListener
		go func() {
			for {
				cc, err := httpListener.Accept()
				if err != nil {
					return
				}
				var buf [4]byte
				_, err = cc.Read(buf[:])
				assert.NoError(t, err)
				_, err = cc.Write([]byte("pong"))
				assert.NoError(t, err)
			}
		}()

		{
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)

			n, err := cc.Write([]byte{0x37, 0x32})
			assert.Equal(t, 2, n)
			require.NoError(t, err)

		}

		{
			// dials will still go through and be placed in the backlog
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)

			_, err = cc.Write([]byte("ping")) // intentionally send a message smaller than the header
			require.NoError(t, err)
			var buf [4]byte
			cc.SetReadDeadline(time.Now().Add(1 * time.Second))
			_, err = cc.Read(buf[:])
			require.NoError(t, err)
			assert.Equal(t, "pong", string(buf[:]))
			cc.Close()
		}

		return true
	})
}

func TestListenerMux_AcceptedConnectionsStayOpenAfterListenerClose(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
		t.Cleanup(func() { assert.NoError(t, grpcListener.Close()) })

		cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
		require.NoError(t, err)

		cc.Write([]byte("foo"))

		sc, err := httpListener.Accept()
		require.NoError(t, err)
		var buf [3]byte
		_, err = sc.Read(buf[:])
		require.NoError(t, err)
		assert.Equal(t, "foo", string(buf[:]))

		httpListener.Close()

		{
			_, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.ErrorContains(t, err, "connection refused")
		}

		cc.Write([]byte("bar"))
		require.NoError(t, err)
		_, err = sc.Read(buf[:])
		require.NoError(t, err)
		assert.Equal(t, "bar", string(buf[:]))

		require.NoError(t, sc.Close())
		require.NoError(t, cc.Close())

		return false
	})
}

func TestListenerMux_ClientClosesImmediatelyAfterDial(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, _ net.Listener, _ bool) (shouldCleanup bool) {
		cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
		require.NoError(t, err)
		require.NoError(t, cc.Close())

		return true
	})
}

func TestListenerMux_ClosingListenerClosesPendingConns(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
		for range 3 {
			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)
			require.NoError(t, cc.Close())
		}
		done := make(chan struct{}, 10)
		for range cap(done) {
			go func() {
				defer func() {
					done <- struct{}{}
				}()
				cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
				require.NoError(t, err)
				var data [1]byte
				n, err := cc.Read(data[:])
				assert.Equal(t, 0, n)
				assert.Error(t, err)
			}()
		}

		time.Sleep(netutil.InitialRecvTimeout / 2)

		assert.NoError(t, httpListener.Close())
		timeout := time.After(1 * time.Second)
	LOOP:
		for i := range cap(done) {
			select {
			case <-done:
			case <-timeout:
				t.Errorf("timed out waiting for %d connections to close", cap(done)-i)
				break LOOP
			}
		}

		assert.NoError(t, grpcListener.Close())

		return false
	})
}

func TestListenerMux_ReAddAfterClose(t *testing.T) {
	mux := netutil.NewListenerMux(zerolog.New(zerolog.NewTestWriter(t)))
	for range 5 {
		httpListener, err := mux.Listen("tcp", "127.0.0.1:0", "http")
		require.NoError(t, err)

		cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
		require.NoError(t, err)

		httpListener.Close()
		assertConnectionClosed(t, cc)
	}

	httpListener, err := mux.Listen("tcp", "127.0.0.1:0", "http")
	require.NoError(t, err)
	for range 5 {
		grpcListener, err := mux.Listen("tcp", "127.0.0.1:0", "grpc")
		require.NoError(t, err)

		cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
		require.NoError(t, err)

		_, err = cc.Write(append(
			[]byte{0x37, 0x32, 0x36, 0x31, byte(len("grpc"))},
			"grpc"...))
		require.NoError(t, err)

		grpcListener.Close() // close before the connection can be accepted
		assertConnectionClosed(t, cc)
	}
	for range 5 {
		virtualGrpcListener := mux.AddVirtualListener(httpListener.Addr(), "grpc")

		cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
		require.NoError(t, err)

		_, err = cc.Write(append(
			[]byte{0x37, 0x32, 0x36, 0x31, byte(len("grpc"))},
			"grpc"...))
		require.NoError(t, err)

		virtualGrpcListener.Close() // close before the connection can be accepted
		assertConnectionClosed(t, cc)
	}
	require.NoError(t, httpListener.Close())
}

func TestListenerMux_OtherProtocols(t *testing.T) {
	for _, tc := range []struct {
		network string
		addr    string
	}{
		{"tcp6", "[::]:0"},
		{"unix", path.Join(t.TempDir(), "sock")},
	} {
		t.Run("", func(t *testing.T) {
			mux := netutil.NewListenerMux(zerolog.New(zerolog.NewTestWriter(t)))
			httpListener, err := mux.Listen(tc.network, tc.addr, "http")
			require.NoError(t, err)

			cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err)
			cc.Write([]byte("hello world"))

			sc, err := httpListener.Accept()
			require.NoError(t, err)
			var data [11]byte
			n, err := sc.Read(data[:])
			require.Equal(t, 11, n)
			require.NoError(t, err)

			require.NoError(t, cc.Close())

			require.NoError(t, httpListener.Close())
		})
	}
}

func TestListenerMux_CloseBeforeAnyConnectionsAccepted(t *testing.T) {
	mux := netutil.NewListenerMux(zerolog.New(zerolog.NewTestWriter(t)))
	{
		l, err := mux.Listen("tcp", "127.0.0.1:0", "http")
		assert.NoError(t, err)
		assert.NoError(t, l.Close())
	}
	{
		// mux with only virtual listeners is useless, but this at least shouldn't
		// try to bind to the address or anything
		l := mux.AddVirtualListener(
			net.TCPAddrFromAddrPort(netip.MustParseAddrPort("255.255.255.255:1")), "http")
		assert.NoError(t, l.Close())
	}
}

func TestListenerMux_ListenError(t *testing.T) {
	mux := netutil.NewListenerMux(zerolog.New(zerolog.NewTestWriter(t)))
	_, err := mux.Listen("foo", "bar", "baz")
	assert.Error(t, err)

	l, err := mux.Listen("tcp", "127.0.0.1:0", "http")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, l.Close())
	})
	assert.Panics(t, func() {
		mux.Listen("tcp", "127.0.0.1:0", "http")
	})
	assert.Panics(t, func() {
		mux.AddVirtualListener(l.Addr(), "http")
	})
}

func TestListenerMux_CloseTwice(t *testing.T) {
	testNormalAndVirtualListeners(t, func(t *testing.T, httpListener, grpcListener net.Listener, _ bool) (shouldCleanup bool) {
		assert.NoError(t, httpListener.Close())
		assert.ErrorIs(t, httpListener.Close(), net.ErrClosed)
		assert.NoError(t, grpcListener.Close())
		assert.ErrorIs(t, grpcListener.Close(), net.ErrClosed)
		return false
	})
}

func TestListenerMux_NonClosedAcceptErrorPassthrough(t *testing.T) {
	// This tests the (unusual) case of Accept() on the real listener returning
	// an error other than one that indicates the listener has been closed.
	// In practice this happens from fd exhaustion or oom. When such an error
	// occurs it should be forwarded to the proxy listener's Accept(), and the
	// real listener should not be closed.
	if runtime.GOOS != "linux" {
		// the rlimit trick used here doesn't work on macos
		t.Skip()
	}
	mux := netutil.NewListenerMux(zerolog.New(zerolog.NewTestWriter(t)))

	var originalRlimit unix.Rlimit
	assert.NoError(t, unix.Getrlimit(unix.RLIMIT_NOFILE, &originalRlimit))

	var success bool
	var httpListener net.Listener
	// If RLIMIT_NOFILE is set to 0 before Accept is called on the real listener
	// (but after the listener is created), it will immediately return with
	// EMFILE. However if Accept is called before the rlimit update takes effect,
	// accept will remain blocked. Try several times to start the listener and
	// then set the rlimit to 0 before the accept loop goroutine is scheduled.
LOOP:
	for i := range 10 {
		var err error
		httpListener, err = mux.Listen("tcp", "127.0.0.1:0", "http")
		require.NoError(t, err)

		assert.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
			Cur: 0,
			Max: originalRlimit.Max,
		}))

		acceptErr := make(chan error, 1)
		go func() {
			_, err := httpListener.Accept()
			acceptErr <- err
		}()

		select {
		case err := <-acceptErr:
			if errors.Is(err, syscall.EMFILE) {
				// success
				success = true
				t.Logf("succeeded in %d attempts", i+1)
				break LOOP
			}
			// if accept fails, it will fail immediately
		case <-time.After(10 * time.Millisecond):
			httpListener.Close()
			<-acceptErr
		}

		// restore the rlimit and try again
		assert.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &originalRlimit))
	}

	require.True(t, success)

	assert.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &originalRlimit))

	// After the first Accept failed on the real listener and the proxy listener
	// calls Accept to receive the error, Accept will be called again on the real
	// listener right away. That will happen before the rlimit is able to be
	// restored, so it will fail with the same error. The ListenerMux will again
	// wait for the proxy listener to call Accept to receive the error (or for it
	// to to close), so there will be one pending error to read first. Once this
	// is read then Accept will be called a third time on the real listener, but
	// the rlimit will have been restored so it will block and wait.
	_, err := httpListener.Accept()
	require.ErrorIs(t, err, syscall.EMFILE)

	{
		cc, err := net.Dial(httpListener.Addr().Network(), httpListener.Addr().String())
		require.NoError(t, err)
		cc.Write([]byte("hello world"))

		sc, err := httpListener.Accept()
		require.NoError(t, err)
		var data [11]byte
		n, err := sc.Read(data[:])
		assert.Equal(t, 11, n)
		assert.NoError(t, err)
		assert.Equal(t, "hello world", string(data[:]))

		assert.NoError(t, sc.Close())
		assert.NoError(t, cc.Close())
	}

	assert.NoError(t, httpListener.Close())
}

func assertConnectionClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))
	var b [1]byte
	n, err := conn.Read(b[:])
	t.Logf("conn.Read returned after %s with error %s", time.Since(start), err)
	assert.Equal(t, 0, n)
	assert.NotContains(t, err.Error(), "i/o timeout") // from SetReadDeadline ^
	// the error received depends on if the connection is closed while
	// waiting to peek the header or while waiting to read the payload,
	// but it must not be the above read deadline timeout
	assert.Truef(t, strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection reset by peer"),
		"error '%s' does not contain 'EOF' or 'connection reset by peer", err.Error())
}
