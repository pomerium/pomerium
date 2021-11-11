package cli_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/cli"
	"github.com/pomerium/pomerium/internal/testutil"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

func TestListenerServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := cli.NewServer(ctx)
	require.NoError(t, err)

	rec, err := srv.Upsert(ctx, &pb.Record{
		Tags: []string{"test"},
		Conn: &pb.Connection{
			RemoteAddr: "tcp.localhost.pomerium.io:99",
			ListenAddr: testutil.StrP(":0"),
		},
	})
	require.NoError(t, err)
	id := rec.GetId()
	require.NotEmpty(t, id)

	status, err := srv.Update(ctx, &pb.ListenerUpdateRequest{
		ConnectionIds: []string{id},
		Connected:     true,
	})
	require.NoError(t, err)

	cs, there := status.Listeners[id]
	require.True(t, there)
	require.NotNil(t, cs.ListenAddr)
	require.True(t, cs.Listening)
	require.Nil(t, cs.LastError)
	listenAddr := *cs.ListenAddr

	_, err = net.Listen("tcp", listenAddr)
	assert.Error(t, err)

	for k, sel := range map[string]*pb.Selector{
		"all":    {All: true},
		"by tag": {Tags: []string{"test"}},
		"by id":  {Ids: []string{id}},
	} {
		status, err = srv.GetStatus(ctx, sel)
		if assert.NoError(t, err, k) && assert.Contains(t, status.Listeners, id, k) {
			if assert.NotNil(t, status.Listeners[id].ListenAddr, k) {
				assert.Equal(t, listenAddr, *status.Listeners[id].ListenAddr, k)
			}
			assert.True(t, status.Listeners[id].Listening, k)
			assert.Nil(t, status.Listeners[id].LastError, k)
		}
	}

	// update should be idempotent
	status, err = srv.Update(ctx, &pb.ListenerUpdateRequest{
		ConnectionIds: []string{id},
		Connected:     true,
	})
	if assert.NoError(t, err) && assert.Contains(t, status.Listeners, id) {
		assert.True(t, status.Listeners[id].Listening)
		if assert.NotNil(t, status.Listeners[id].ListenAddr) {
			assert.Equal(t, listenAddr, *status.Listeners[id].ListenAddr)
		}
		assert.Nil(t, status.Listeners[id].LastError)
	}

	status, err = srv.Update(ctx, &pb.ListenerUpdateRequest{
		ConnectionIds: []string{id},
		Connected:     false,
	})
	if assert.NoError(t, err) && assert.Contains(t, status.Listeners, id) {
		assert.False(t, status.Listeners[id].Listening)
		assert.Nil(t, status.Listeners[id].ListenAddr)
		assert.Nil(t, status.Listeners[id].LastError)
	}

	status, err = srv.GetStatus(ctx, &pb.Selector{All: true})
	if assert.NoError(t, err) && assert.Contains(t, status.Listeners, id) {
		assert.False(t, status.Listeners[id].Listening)
		assert.Nil(t, status.Listeners[id].ListenAddr)
		assert.Nil(t, status.Listeners[id].LastError)
	}

	// ensure listener is shut down
	assert.Eventually(t, func() bool {
		conn, err := net.Listen("tcp", listenAddr)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, time.Second*2, time.Millisecond*100)
}
