package postgresproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"
)

func TestPreparePGConnConfigIgnoresAmbientConnectionSettings(t *testing.T) {
	t.Setenv("PGHOST", "attacker.invalid")
	t.Setenv("PGPORT", "6543")
	t.Setenv("PGUSER", "attacker")
	t.Setenv("PGPASSWORD", "ambient-secret")
	t.Setenv("PGDATABASE", "attacker-db")
	t.Setenv("PGSSLMODE", "disable")
	t.Setenv("PGAPPNAME", "attacker-app")
	t.Setenv("PGOPTIONS", "-c search_path=attacker")

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "database.internal"}
	cfg, err := preparePGConnConfig(
		&UpstreamTarget{Addr: "database.internal:5432", TLSConfig: tlsConfig},
		&Session{ApplicationName: "route-owned-app"},
		pgproto3.ProtocolVersion30,
		17*time.Second,
	)
	require.NoError(t, err)
	require.Equal(t, "database.internal", cfg.Host)
	require.Equal(t, uint16(5432), cfg.Port)
	require.Empty(t, cfg.User)
	require.Empty(t, cfg.Password)
	require.Empty(t, cfg.Database)
	require.Same(t, tlsConfig, cfg.TLSConfig)
	require.Empty(t, cfg.Fallbacks)
	require.Equal(t, "disable", cfg.ChannelBinding)
	require.Equal(t, "postgres", cfg.SSLNegotiation)
	require.Equal(t, 17*time.Second, cfg.ConnectTimeout)
	require.Equal(t, map[string]string{"application_name": "route-owned-app"}, cfg.RuntimeParams)
	require.Empty(t, cfg.KerberosSrvName)
	require.Empty(t, cfg.KerberosSpn)
	require.Nil(t, cfg.ValidateConnect)
	require.Nil(t, cfg.AfterConnect)
	require.Nil(t, cfg.AfterNetConnect)
	require.NotNil(t, cfg.OnPgError, "safe library FATAL-error handling must be preserved")
	require.NotNil(t, cfg.BuildContextWatcherHandler)
	require.NotNil(t, cfg.DialFunc)
	require.NotNil(t, cfg.LookupFunc)
	require.Nil(t, cfg.OAuthTokenProvider)
}

func TestPreparePGConnConfigNeverMutatesProcessEnvironment(t *testing.T) {
	const canary = "postgres-env-canary"
	t.Setenv("PGPASSWORD", canary)
	var changed atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10000 {
			if os.Getenv("PGPASSWORD") != canary {
				changed.Store(true)
				return
			}
		}
	}()
	for range 100 {
		_, err := preparePGConnConfig(&UpstreamTarget{Addr: "127.0.0.1:5432"}, &Session{}, pgproto3.ProtocolVersion30, time.Second)
		require.NoError(t, err)
	}
	<-done
	require.False(t, changed.Load())
	require.Equal(t, canary, os.Getenv("PGPASSWORD"))
}

func TestPreparePGConnConfigInvalidAmbientServiceFailsClosed(t *testing.T) {
	t.Setenv("PGSERVICE", "missing-service")
	t.Setenv("PGSERVICEFILE", t.TempDir()+"/missing-service-file")
	_, err := preparePGConnConfig(&UpstreamTarget{Addr: "127.0.0.1:5432"}, &Session{}, pgproto3.ProtocolVersion30, time.Second)
	require.Error(t, err)
}

func TestForwardCancelBoundsStalledUpstreamIO(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	server := &Server{CancelTimeout: 25 * time.Millisecond}
	key, unregister, err := server.registerCancelKey(pgproto3.BackendKeyData{
		ProcessID: 42,
		SecretKey: []byte{1, 2, 3, 4},
	}, &UpstreamTarget{Addr: listener.Addr().String(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
	require.NoError(t, err)
	defer unregister()

	started := time.Now()
	err = server.forwardCancel(context.Background(), &pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: key.SecretKey})
	require.Error(t, err)
	require.Less(t, time.Since(started), time.Second)
	conn := <-accepted
	_ = conn.Close()
}

func TestPeriodicReauthorizeStopWaitsForWorker(t *testing.T) {
	started := make(chan struct{})
	exited := make(chan struct{})
	server := &Server{
		ReauthorizeInterval: time.Nanosecond,
		Identity: &fakeIdentity{reauthorize: func(ctx context.Context, _ *Session) error {
			close(started)
			<-ctx.Done()
			close(exited)
			return ctx.Err()
		}},
	}
	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	stop := server.startPeriodicReauthorize(t.Context(), &Session{}, client, upstream)
	<-started
	stop()
	select {
	case <-exited:
	default:
		t.Fatal("reauthorization worker was not joined")
	}
}

func TestConnectionLimitIsSharedByServer(t *testing.T) {
	server := &Server{MaxConnections: 1}
	require.True(t, server.acquireConnection())
	require.False(t, server.acquireConnection())
	server.releaseConnection()
	require.True(t, server.acquireConnection())
	server.releaseConnection()
	require.Zero(t, server.active.Load())
}

type errorListener struct{ err error }

func (l errorListener) Accept() (net.Conn, error) { return nil, l.err }
func (errorListener) Close() error                { return nil }
func (errorListener) Addr() net.Addr              { return testAddr("error-listener") }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

func TestServeReturnsAcceptErrorWithoutWaitingForContextCancellation(t *testing.T) {
	want := errors.New("accept failed")
	err := (&Server{}).Serve(t.Context(), errorListener{err: want})
	require.ErrorIs(t, err, want)
}

func TestHandleRejectsUnsupportedStartupProtocolVersion(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	server := &Server{Identity: &fakeIdentity{}, Policy: &fakePolicy{}}
	done := make(chan error, 1)
	go func() { done <- server.Handle(t.Context(), serverConn) }()

	frontend := pgproto3.NewFrontend(clientConn, clientConn)
	frontend.Send(&pgproto3.StartupMessage{ProtocolVersion: 0x00040000, Parameters: map[string]string{"user": "alice"}})
	require.NoError(t, frontend.Flush())
	require.ErrorContains(t, <-done, "unknown startup message code")
	_, err := protocolString(0x00040000)
	require.ErrorContains(t, err, "unsupported postgres protocol version")
}

func TestRegisterCancelKeyRetriesCollisionWithoutOverwriting(t *testing.T) {
	collisionKey := cancelKey(1, []byte{1, 1, 1, 1})
	server := &Server{
		cancelKeys: map[string]pgproto3CancelRequest{
			collisionKey: {ProcessID: 99, SecretKey: []byte{9, 9, 9, 9}},
		},
		random: bytes.NewReader([]byte{
			0, 0, 0, 1, 1, 1, 1, 1,
			0, 0, 0, 2, 2, 2, 2, 2,
		}),
	}
	key, unregister, err := server.registerCancelKey(
		pgproto3.BackendKeyData{ProcessID: 42, SecretKey: []byte{4, 2, 4, 2}},
		&UpstreamTarget{Addr: "127.0.0.1:5432"},
	)
	require.NoError(t, err)
	defer unregister()
	require.Equal(t, uint32(2), key.ProcessID)
	require.Equal(t, []byte{2, 2, 2, 2}, key.SecretKey)
	require.Equal(t, uint32(99), server.cancelKeys[collisionKey].ProcessID)
}

func TestRelayActivityFromEitherDirectionRefreshesBothSockets(t *testing.T) {
	t.Run("frontend", func(t *testing.T) {
		clientProxy, clientPeer := net.Pipe()
		upstreamProxy, upstreamPeer := net.Pipe()
		defer clientPeer.Close()
		defer upstreamPeer.Close()
		client := &deadlineSpyConn{Conn: clientProxy}
		upstream := &deadlineSpyConn{Conn: upstreamProxy}
		activity := &connectionActivity{
			client: client, upstream: upstream, idle: time.Minute,
			absolute: time.Now().Add(time.Hour), now: time.Now,
		}
		activity.waitForClient()
		ctx := context.WithValue(t.Context(), connectionActivityKey{}, activity)
		server := &Server{Identity: &fakeIdentity{}}
		done := make(chan error, 1)
		go func() {
			done <- server.relayFrontendMessages(ctx, &Session{}, pgproto3.NewBackend(client, client), pgproto3.NewFrontend(upstream, upstream))
		}()
		frontend := pgproto3.NewFrontend(clientPeer, clientPeer)
		frontend.Send(&pgproto3.Terminate{})
		require.NoError(t, frontend.Flush())
		msg, err := pgproto3.NewBackend(upstreamPeer, upstreamPeer).Receive()
		require.NoError(t, err)
		require.IsType(t, &pgproto3.Terminate{}, msg)
		require.NoError(t, <-done)
		require.GreaterOrEqual(t, client.deadlineCalls.Load(), int32(2))
		require.GreaterOrEqual(t, upstream.deadlineCalls.Load(), int32(2))
	})

	t.Run("backend", func(t *testing.T) {
		clientProxy, clientPeer := net.Pipe()
		upstreamProxy, upstreamPeer := net.Pipe()
		defer clientPeer.Close()
		client := &deadlineSpyConn{Conn: clientProxy}
		upstream := &deadlineSpyConn{Conn: upstreamProxy}
		activity := &connectionActivity{
			client: client, upstream: upstream, idle: time.Minute,
			absolute: time.Now().Add(time.Hour), now: time.Now,
		}
		activity.frontendReceived(&pgproto3.Query{})
		ctx := context.WithValue(t.Context(), connectionActivityKey{}, activity)
		done := make(chan error, 1)
		go func() {
			done <- relayBackendMessages(ctx, pgproto3.NewFrontend(upstream, upstream), pgproto3.NewBackend(client, client))
		}()
		backend := pgproto3.NewBackend(upstreamPeer, upstreamPeer)
		backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		require.NoError(t, backend.Flush())
		msg, err := pgproto3.NewFrontend(clientPeer, clientPeer).Receive()
		require.NoError(t, err)
		require.IsType(t, &pgproto3.ReadyForQuery{}, msg)
		require.NoError(t, upstreamPeer.Close())
		require.Error(t, <-done)
		require.GreaterOrEqual(t, client.deadlineCalls.Load(), int32(2))
		require.GreaterOrEqual(t, upstream.deadlineCalls.Load(), int32(2))
	})
}

func TestConnectionActivityNeverExtendsAbsoluteDeadline(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	spy := &deadlineSpyConn{Conn: left}
	now := time.Date(2026, 7, 9, 1, 0, 0, 0, time.UTC)
	absolute := now.Add(10 * time.Minute)
	activity := &connectionActivity{client: spy, idle: 30 * time.Minute, absolute: absolute, now: func() time.Time { return now }}
	activity.waitForClient()
	require.Equal(t, absolute, spy.lastDeadline())
	activity.frontendReceived(&pgproto3.Query{})
	require.Equal(t, absolute, spy.lastDeadline())
}

func TestConnectionActivityWaitsForAllPipelinedReadyBoundaries(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	client := &deadlineSpyConn{Conn: clientConn}
	upstream := &deadlineSpyConn{Conn: upstreamConn}
	now := time.Date(2026, 7, 9, 1, 0, 0, 0, time.UTC)
	absolute := now.Add(time.Hour)
	activity := &connectionActivity{
		client: client, upstream: upstream, idle: time.Minute,
		absolute: absolute, now: func() time.Time { return now },
	}

	activity.frontendReceived(&pgproto3.Query{})
	activity.frontendReceived(&pgproto3.Query{})
	activity.backendForwarded(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.Equal(t, absolute, client.lastDeadline(),
		"the first ReadyForQuery must not idle a pipelined second query")
	require.Equal(t, absolute, upstream.lastDeadline())

	activity.backendForwarded(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline())
	require.Equal(t, absolute, upstream.lastDeadline())
}

func TestConnectionActivityCopyInputRefreshesClientIdleDeadline(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	client := &deadlineSpyConn{Conn: clientConn}
	upstream := &deadlineSpyConn{Conn: upstreamConn}
	now := time.Date(2026, 7, 9, 1, 0, 0, 0, time.UTC)
	absolute := now.Add(time.Hour)
	activity := &connectionActivity{
		client: client, upstream: upstream, idle: time.Minute,
		absolute: absolute, now: func() time.Time { return now },
	}

	activity.frontendReceived(&pgproto3.Query{})
	activity.frontendForwarded()
	activity.backendForwarded(&pgproto3.CopyInResponse{})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline())
	require.Equal(t, absolute, upstream.lastDeadline())

	now = now.Add(30 * time.Second)
	activity.frontendReceived(&pgproto3.CopyData{})
	activity.frontendForwarded()
	require.Equal(t, now.Add(time.Minute), client.lastDeadline(),
		"each forwarded CopyData message should refresh the client-input idle deadline")

	activity.frontendReceived(&pgproto3.CopyDone{})
	activity.frontendForwarded()
	require.Equal(t, absolute, client.lastDeadline(),
		"CopyDone should restore the active-operation deadline until ReadyForQuery")
	activity.backendForwarded(&pgproto3.CommandComplete{})
	require.Equal(t, absolute, client.lastDeadline())
	activity.backendForwarded(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline())
}

func TestConnectionActivityExtendedCopyCompletionWaitsForSync(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	client := &deadlineSpyConn{Conn: clientConn}
	upstream := &deadlineSpyConn{Conn: upstreamConn}
	now := time.Date(2026, 7, 9, 1, 0, 0, 0, time.UTC)
	absolute := now.Add(time.Hour)
	activity := &connectionActivity{
		client: client, upstream: upstream, idle: time.Minute,
		absolute: absolute, now: func() time.Time { return now },
	}

	activity.frontendReceived(&pgproto3.Execute{})
	activity.frontendForwarded()
	activity.backendForwarded(&pgproto3.CopyInResponse{})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline())
	activity.frontendReceived(&pgproto3.CopyDone{})
	activity.frontendForwarded()
	require.Equal(t, absolute, client.lastDeadline())

	activity.backendForwarded(&pgproto3.CommandComplete{})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline(),
		"an extended COPY completion without Sync should wait idly for the client")
	activity.frontendReceived(&pgproto3.Sync{})
	activity.frontendForwarded()
	require.Equal(t, absolute, client.lastDeadline())
	activity.backendForwarded(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline())
}

func TestConnectionActivityExtendedExecuteCompletionWaitsForClient(t *testing.T) {
	for _, completion := range []pgproto3.BackendMessage{
		&pgproto3.CommandComplete{},
		&pgproto3.PortalSuspended{},
		&pgproto3.EmptyQueryResponse{},
	} {
		t.Run(fmt.Sprintf("%T", completion), func(t *testing.T) {
			clientConn, clientPeer := net.Pipe()
			upstreamConn, upstreamPeer := net.Pipe()
			defer clientPeer.Close()
			defer upstreamPeer.Close()
			client := &deadlineSpyConn{Conn: clientConn}
			upstream := &deadlineSpyConn{Conn: upstreamConn}
			now := time.Date(2026, 7, 9, 1, 0, 0, 0, time.UTC)
			absolute := now.Add(time.Hour)
			activity := &connectionActivity{
				client: client, upstream: upstream, idle: time.Minute,
				absolute: absolute, now: func() time.Time { return now },
			}

			activity.frontendReceived(&pgproto3.Execute{})
			activity.frontendForwarded()
			require.Equal(t, absolute, client.lastDeadline())
			activity.backendForwarded(completion)
			require.Equal(t, now.Add(time.Minute), client.lastDeadline())
			require.Equal(t, absolute, upstream.lastDeadline())
		})
	}
}

func TestConnectionActivityFunctionCallReadyDoesNotConsumePipelinedQuery(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	client := &deadlineSpyConn{Conn: clientConn}
	upstream := &deadlineSpyConn{Conn: upstreamConn}
	now := time.Date(2026, 7, 9, 1, 0, 0, 0, time.UTC)
	absolute := now.Add(time.Hour)
	activity := &connectionActivity{
		client: client, upstream: upstream, idle: time.Minute,
		absolute: absolute, now: func() time.Time { return now },
	}

	activity.frontendReceived(&pgproto3.FunctionCall{})
	activity.frontendForwarded()
	activity.frontendReceived(&pgproto3.Query{})
	activity.frontendForwarded()
	activity.backendForwarded(&pgproto3.FunctionCallResponse{})
	require.Equal(t, absolute, client.lastDeadline())
	activity.backendForwarded(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.Equal(t, absolute, client.lastDeadline(),
		"the FunctionCall ReadyForQuery must leave the pipelined Query active")
	activity.backendForwarded(&pgproto3.CommandComplete{})
	activity.backendForwarded(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline())
}

func TestConnectionActivityExtendedErrorKeepsSkippedWorkIdleUntilSync(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	client := &deadlineSpyConn{Conn: clientConn}
	upstream := &deadlineSpyConn{Conn: upstreamConn}
	now := time.Date(2026, 7, 9, 1, 0, 0, 0, time.UTC)
	absolute := now.Add(time.Hour)
	activity := &connectionActivity{
		client: client, upstream: upstream, idle: time.Minute,
		absolute: absolute, now: func() time.Time { return now },
	}

	activity.frontendReceived(&pgproto3.Parse{})
	activity.frontendForwarded()
	activity.backendForwarded(&pgproto3.ErrorResponse{})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline())

	activity.frontendReceived(&pgproto3.Execute{})
	activity.frontendForwarded()
	require.Equal(t, now.Add(time.Minute), client.lastDeadline(),
		"an Execute skipped after ErrorResponse must not suppress client idle")

	activity.frontendReceived(&pgproto3.Sync{})
	activity.frontendForwarded()
	require.Equal(t, absolute, client.lastDeadline())
	activity.backendForwarded(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.Equal(t, now.Add(time.Minute), client.lastDeadline())
}

func TestNeutralRelayCleansUpOnEitherHalfClose(t *testing.T) {
	for _, closeClient := range []bool{true, false} {
		name := "upstream"
		if closeClient {
			name = "client"
		}
		t.Run(name, func(t *testing.T) {
			clientProxy, clientPeer := tcpConnPair(t)
			upstreamProxy, upstreamPeer := tcpConnPair(t)
			defer clientPeer.Close()
			defer upstreamPeer.Close()
			server := &Server{Identity: &fakeIdentity{}}
			done := make(chan error, 1)
			go func() {
				done <- server.relay(t.Context(), &Session{}, pgproto3.NewBackend(clientProxy, clientProxy), clientProxy, pgproto3.NewFrontend(upstreamProxy, upstreamProxy), upstreamProxy)
			}()
			if closeClient {
				require.NoError(t, clientPeer.CloseWrite())
				require.NoError(t, upstreamPeer.SetReadDeadline(time.Now().Add(time.Second)))
				_, err := upstreamPeer.Read(make([]byte, 1))
				require.Error(t, err)
			} else {
				require.NoError(t, upstreamPeer.CloseWrite())
				require.NoError(t, clientPeer.SetReadDeadline(time.Now().Add(time.Second)))
				_, err := clientPeer.Read(make([]byte, 1))
				require.Error(t, err)
			}
			require.NoError(t, <-done)
		})
	}
}

func TestStartupDeadlineBoundsSilentClient(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	server := &Server{StartupTimeout: 20 * time.Millisecond, Identity: &fakeIdentity{}, Policy: &fakePolicy{}}
	started := time.Now()
	err := server.Handle(t.Context(), serverConn)
	require.Error(t, err)
	require.Less(t, time.Since(started), time.Second)
}

type deadlineSpyConn struct {
	net.Conn
	deadlineCalls atomic.Int32
	mu            sync.Mutex
	deadline      time.Time
}

func (c *deadlineSpyConn) SetDeadline(deadline time.Time) error {
	c.deadlineCalls.Add(1)
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func (c *deadlineSpyConn) lastDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

func tcpConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	return <-accepted, peer
}
