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

	var listenAddr string
	if assert.Contains(t, status.Active, id) {
		listenAddr = status.Active[id]
	}
	assert.Empty(t, status.Errors)

	_, err = net.Listen("tcp", listenAddr)
	assert.Error(t, err)

	for k, sel := range map[string]*pb.Selector{
		"all": {All: true},
	} {
		status, err = srv.GetStatus(ctx, sel)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{id: listenAddr}, status.Active, k)
		assert.Empty(t, status.Errors, k)
	}

	status, err = srv.Update(ctx, &pb.ListenerUpdateRequest{
		ConnectionIds: []string{id},
		Connected:     true,
	})
	if assert.NoError(t, err) {
		assert.Empty(t, status.Active)
		assert.Contains(t, status.Errors, id)
	}

	status, err = srv.Update(ctx, &pb.ListenerUpdateRequest{
		ConnectionIds: []string{id},
		Connected:     false,
	})
	if assert.NoError(t, err) {
		assert.Empty(t, status.Active)
		assert.Empty(t, status.Errors)
	}

	status, err = srv.GetStatus(ctx, &pb.Selector{All: true})
	if assert.NoError(t, err) {
		assert.Empty(t, status.Active)
		assert.Empty(t, status.Errors)
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
