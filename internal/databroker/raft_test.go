package databroker_test

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type testRaftDataBrokerServiceServer struct {
	srv databrokerpb.RaftServer
	databrokerpb.UnimplementedDataBrokerServiceServer
}

func (s testRaftDataBrokerServiceServer) Raft(stream grpc.BidiStreamingServer[databrokerpb.RaftRequest, databrokerpb.RaftResponse]) error {
	return s.srv.ServeRaft(stream)
}

func TestRaft(t *testing.T) {
	t.Parallel()

	startServer := func() (raft.ServerAddress, databrokerpb.RaftServer) {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = li.Close() })
		s := grpc.NewServer()
		t.Cleanup(s.Stop)
		srv := databrokerpb.NewRaftServer(raft.ServerAddress(li.Addr().String()))
		t.Cleanup(srv.Stop)
		databrokerpb.RegisterDataBrokerServiceServer(s, testRaftDataBrokerServiceServer{srv: srv})
		go s.Serve(li)
		return raft.ServerAddress("http://" + li.Addr().String()), srv
	}

	addr1, s1 := startServer()
	addr2, s2 := startServer()
	addr3, s3 := startServer()

	cfg := &config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.DataBroker.ClusterNodes = []config.DataBrokerClusterNode{
		{
			ID:          "node-1",
			GRPCAddress: string(addr1),
		}, {
			ID:          "node-2",
			GRPCAddress: string(addr2),
		}, {
			ID:          "node-3",
			GRPCAddress: string(addr3),
		},
	}

	clientManager := databroker.NewClientManager(noop.NewTracerProvider())
	clientManager.OnConfigChange(t.Context(), cfg)

	cfg1 := cfg.Clone()
	cfg1.Options.DataBroker.ClusterNodeID = null.StringFrom("node-1")
	r1, err := databroker.NewRaft(cfg1.Options.DataBroker, s1, clientManager)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r1.Shutdown().Error() })

	cfg2 := cfg.Clone()
	cfg2.Options.DataBroker.ClusterNodeID = null.StringFrom("node-2")
	r2, err := databroker.NewRaft(cfg2.Options.DataBroker, s2, clientManager)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r2.Shutdown().Error() })

	cfg3 := cfg.Clone()
	cfg3.Options.DataBroker.ClusterNodeID = null.StringFrom("node-3")
	r3, err := databroker.NewRaft(cfg3.Options.DataBroker, s3, clientManager)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r3.Shutdown().Error() })

	assert.Eventually(t, func() bool {
		return r1.Leader() != ""
	}, 10*time.Second, 100*time.Millisecond)
}
