package postgresproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestReauthorizationBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msgs []pgproto3.FrontendMessage
		want []bool
	}{
		{
			name: "simple queries and function calls",
			msgs: []pgproto3.FrontendMessage{
				&pgproto3.Query{},
				&pgproto3.Query{},
				&pgproto3.FunctionCall{},
			},
			want: []bool{true, true, true},
		},
		{
			name: "extended cycle and every execute",
			msgs: []pgproto3.FrontendMessage{
				&pgproto3.Parse{},
				&pgproto3.Bind{},
				&pgproto3.Describe{},
				&pgproto3.Execute{},
				&pgproto3.Execute{},
				&pgproto3.Flush{},
				&pgproto3.Sync{},
				&pgproto3.Close{},
				&pgproto3.Sync{},
			},
			want: []bool{true, false, false, true, true, false, false, true, false},
		},
		{
			name: "copy stream belongs to authorized query",
			msgs: []pgproto3.FrontendMessage{
				&pgproto3.Query{},
				&pgproto3.CopyData{},
				&pgproto3.CopyDone{},
			},
			want: []bool{true, false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var boundaries reauthorizationBoundaries
			got := make([]bool, 0, len(tt.msgs))
			for _, msg := range tt.msgs {
				got = append(got, boundaries.before(msg))
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNeutralRelayIdleTimeoutDoesNotBoundActiveOperation(t *testing.T) {
	for _, extended := range []bool{false, true} {
		name := "simple"
		if extended {
			name = "extended"
		}
		t.Run(name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

			const idleTimeout = 40 * time.Millisecond
			clientProxy, clientPeer := tcpConnPair(t)
			upstreamProxy, upstreamPeer := tcpConnPair(t)
			defer clientPeer.Close()
			defer upstreamPeer.Close()
			testDeadline := time.Now().Add(5 * time.Second)
			require.NoError(t, clientPeer.SetDeadline(testDeadline))
			require.NoError(t, upstreamPeer.SetDeadline(testDeadline))

			activity := &connectionActivity{
				client:   clientProxy,
				upstream: upstreamProxy,
				idle:     idleTimeout,
				absolute: testDeadline,
				now:      time.Now,
			}
			activity.waitForClient()
			ctx := context.WithValue(t.Context(), connectionActivityKey{}, activity)
			server := &Server{Identity: &fakeIdentity{}}
			done := make(chan error, 1)
			go func() {
				done <- server.relay(ctx, &Session{}, pgproto3.NewBackend(clientProxy, clientProxy), clientProxy,
					pgproto3.NewFrontend(upstreamProxy, upstreamProxy), upstreamProxy)
			}()

			client := pgproto3.NewFrontend(clientPeer, clientPeer)
			upstream := pgproto3.NewBackend(upstreamPeer, upstreamPeer)
			if extended {
				client.Send(&pgproto3.Parse{Name: "statement", Query: "select pg_sleep(1)"})
				client.Send(&pgproto3.Bind{PreparedStatement: "statement", DestinationPortal: "portal"})
				client.Send(&pgproto3.Execute{Portal: "portal"})
				client.Send(&pgproto3.Sync{})
				require.NoError(t, client.Flush())
			} else {
				encoded, err := (&pgproto3.Query{String: "select pg_sleep(1)"}).Encode(nil)
				require.NoError(t, err)
				_, err = clientPeer.Write(encoded[:3])
				require.NoError(t, err)
				_, err = clientPeer.Write(encoded[3:])
				require.NoError(t, err)
			}

			frontendMessages := 1
			if extended {
				frontendMessages = 4
			}
			for range frontendMessages {
				_, err := upstream.Receive()
				require.NoError(t, err)
			}
			if extended {
				upstream.Send(&pgproto3.ParseComplete{})
				upstream.Send(&pgproto3.BindComplete{})
				require.NoError(t, upstream.Flush())
				for _, want := range []pgproto3.BackendMessage{&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}} {
					msg, err := client.Receive()
					require.NoError(t, err)
					require.IsType(t, want, msg)
				}
			}

			// The upstream operation is deliberately silent for several idle
			// intervals. The proxy must retain only the absolute connection bound
			// until ReadyForQuery returns control to the client.
			time.Sleep(4 * idleTimeout)
			upstream.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			upstream.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			require.NoError(t, upstream.Flush())

			msg, err := client.Receive()
			require.NoError(t, err)
			require.IsType(t, &pgproto3.CommandComplete{}, msg)
			msg, err = client.Receive()
			require.NoError(t, err)
			require.IsType(t, &pgproto3.ReadyForQuery{}, msg)

			client.Send(&pgproto3.Terminate{})
			require.NoError(t, client.Flush())
			frontendMsg, err := upstream.Receive()
			require.NoError(t, err)
			require.IsType(t, &pgproto3.Terminate{}, frontendMsg)
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("neutral relay did not stop after Terminate")
			}
		})
	}
}

func TestNeutralRelayIdleTimeoutExpiresWaitingClient(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	const idleTimeout = 40 * time.Millisecond
	clientProxy, clientPeer := tcpConnPair(t)
	upstreamProxy, upstreamPeer := tcpConnPair(t)
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	testDeadline := time.Now().Add(5 * time.Second)
	require.NoError(t, clientPeer.SetDeadline(testDeadline))
	require.NoError(t, upstreamPeer.SetDeadline(testDeadline))
	activity := &connectionActivity{
		client:   clientProxy,
		upstream: upstreamProxy,
		idle:     idleTimeout,
		absolute: testDeadline,
		now:      time.Now,
	}
	activity.waitForClient()
	ctx := context.WithValue(t.Context(), connectionActivityKey{}, activity)
	server := &Server{Identity: &fakeIdentity{}}
	done := make(chan error, 1)
	go func() {
		done <- server.relay(ctx, &Session{}, pgproto3.NewBackend(clientProxy, clientProxy), clientProxy,
			pgproto3.NewFrontend(upstreamProxy, upstreamProxy), upstreamProxy)
	}()
	client := pgproto3.NewFrontend(clientPeer, clientPeer)
	upstream := pgproto3.NewBackend(upstreamPeer, upstreamPeer)
	client.Send(&pgproto3.Query{String: "select 1"})
	require.NoError(t, client.Flush())
	msg, err := upstream.Receive()
	require.NoError(t, err)
	require.IsType(t, &pgproto3.Query{}, msg)
	upstream.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
	upstream.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	require.NoError(t, upstream.Flush())
	backendMsg, err := client.Receive()
	require.NoError(t, err)
	require.IsType(t, &pgproto3.CommandComplete{}, backendMsg)
	backendMsg, err = client.Receive()
	require.NoError(t, err)
	require.IsType(t, &pgproto3.ReadyForQuery{}, backendMsg)
	started := time.Now()

	select {
	case err = <-done:
		requireRelayIdleTimeout(t, err, started, idleTimeout)
	case <-time.After(time.Second):
		t.Fatal("neutral relay did not expire a client waiting at ReadyForQuery")
	}
}

func TestNeutralRelayIdleTimeoutExpiresIncompleteExtendedCycle(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	const idleTimeout = 40 * time.Millisecond
	clientProxy, clientPeer := tcpConnPair(t)
	upstreamProxy, upstreamPeer := tcpConnPair(t)
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	testDeadline := time.Now().Add(5 * time.Second)
	require.NoError(t, clientPeer.SetDeadline(testDeadline))
	require.NoError(t, upstreamPeer.SetDeadline(testDeadline))
	activity := &connectionActivity{
		client: clientProxy, upstream: upstreamProxy, idle: idleTimeout,
		absolute: testDeadline, now: time.Now,
	}
	activity.waitForClient()
	ctx := context.WithValue(t.Context(), connectionActivityKey{}, activity)
	server := &Server{Identity: &fakeIdentity{}}
	done := make(chan error, 1)
	go func() {
		done <- server.relay(ctx, &Session{}, pgproto3.NewBackend(clientProxy, clientProxy), clientProxy,
			pgproto3.NewFrontend(upstreamProxy, upstreamProxy), upstreamProxy)
	}()

	client := pgproto3.NewFrontend(clientPeer, clientPeer)
	upstream := pgproto3.NewBackend(upstreamPeer, upstreamPeer)
	client.Send(&pgproto3.Parse{Name: "statement", Query: "select $1::int"})
	client.Send(&pgproto3.Bind{PreparedStatement: "statement", DestinationPortal: "portal"})
	require.NoError(t, client.Flush())
	for _, want := range []pgproto3.FrontendMessage{&pgproto3.Parse{}, &pgproto3.Bind{}} {
		msg, err := upstream.Receive()
		require.NoError(t, err)
		require.IsType(t, want, msg)
	}
	upstream.Send(&pgproto3.ParseComplete{})
	upstream.Send(&pgproto3.BindComplete{})
	require.NoError(t, upstream.Flush())
	for _, want := range []pgproto3.BackendMessage{&pgproto3.ParseComplete{}, &pgproto3.BindComplete{}} {
		msg, err := client.Receive()
		require.NoError(t, err)
		require.IsType(t, want, msg)
	}

	started := time.Now()
	select {
	case err := <-done:
		requireRelayIdleTimeout(t, err, started, idleTimeout)
	case <-time.After(time.Second):
		t.Fatal("neutral relay did not expire an incomplete metadata-only extended cycle")
	}
}

func TestNeutralRelayIdleTimeoutExpiresStalledCopyInput(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	const idleTimeout = 40 * time.Millisecond
	clientProxy, clientPeer := tcpConnPair(t)
	upstreamProxy, upstreamPeer := tcpConnPair(t)
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	testDeadline := time.Now().Add(5 * time.Second)
	require.NoError(t, clientPeer.SetDeadline(testDeadline))
	require.NoError(t, upstreamPeer.SetDeadline(testDeadline))
	activity := &connectionActivity{
		client: clientProxy, upstream: upstreamProxy, idle: idleTimeout,
		absolute: testDeadline, now: time.Now,
	}
	activity.waitForClient()
	ctx := context.WithValue(t.Context(), connectionActivityKey{}, activity)
	server := &Server{Identity: &fakeIdentity{}}
	done := make(chan error, 1)
	go func() {
		done <- server.relay(ctx, &Session{}, pgproto3.NewBackend(clientProxy, clientProxy), clientProxy,
			pgproto3.NewFrontend(upstreamProxy, upstreamProxy), upstreamProxy)
	}()

	client := pgproto3.NewFrontend(clientPeer, clientPeer)
	upstream := pgproto3.NewBackend(upstreamPeer, upstreamPeer)
	client.Send(&pgproto3.Query{String: "copy records from stdin"})
	require.NoError(t, client.Flush())
	msg, err := upstream.Receive()
	require.NoError(t, err)
	require.IsType(t, &pgproto3.Query{}, msg)
	upstream.Send(&pgproto3.CopyInResponse{})
	require.NoError(t, upstream.Flush())
	backendMsg, err := client.Receive()
	require.NoError(t, err)
	require.IsType(t, &pgproto3.CopyInResponse{}, backendMsg)

	started := time.Now()
	select {
	case err = <-done:
		requireRelayIdleTimeout(t, err, started, idleTimeout)
	case <-time.After(time.Second):
		t.Fatal("neutral relay did not expire a client stalled in COPY input")
	}
}

func requireRelayIdleTimeout(t *testing.T, err error, started time.Time, idleTimeout time.Duration) {
	t.Helper()
	require.Error(t, err)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())
	require.GreaterOrEqual(t, time.Since(started), idleTimeout/2)
}
