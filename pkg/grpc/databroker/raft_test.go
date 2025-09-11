package databroker_test

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	hclogzerolog "github.com/weastur/hclog-zerolog"
	"go.opentelemetry.io/otel/trace/noop"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type testRaftDataBrokerServiceServer struct {
	srv databroker.RaftServer
	databroker.UnimplementedDataBrokerServiceServer
}

func (s testRaftDataBrokerServiceServer) Raft(stream grpc.BidiStreamingServer[databroker.RaftRequest, databroker.RaftResponse]) error {
	return s.srv.ServeRaft(stream)
}

func TestRaftServer(t *testing.T) {
	t.Parallel()

	startServer := func() (raft.ServerAddress, databroker.RaftServer) {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = li.Close() })
		s := grpc.NewServer()
		t.Cleanup(s.Stop)
		srv := databroker.NewRaftServer(raft.ServerAddress(li.Addr().String()))
		t.Cleanup(srv.Stop)
		databroker.RegisterDataBrokerServiceServer(s, testRaftDataBrokerServiceServer{srv: srv})
		go s.Serve(li)
		return raft.ServerAddress(li.Addr().String()), srv
	}

	clientManager := grpcutil.NewClientManager(noop.NewTracerProvider(),
		grpcutil.WithClientManagerNewClient(func(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
			return grpc.NewClient(target, append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))...)
		}))

	addr1, srv1 := startServer()
	addr2, srv2 := startServer()
	addr3, srv3 := startServer()

	t1 := srv1.Transport(clientManager)
	t2 := srv2.Transport(clientManager)
	t3 := srv3.Transport(clientManager)

	cfg1 := raft.DefaultConfig()
	cfg1.LocalID = "node-1"
	cfg1.Logger = hclogzerolog.NewWithCustomNameField(log.Logger().With().Str("component", "raft").Str("node", "node-1").Logger(), "name")
	r1, err := raft.NewRaft(cfg1, &raft.MockFSM{}, raft.NewInmemStore(), raft.NewInmemStore(), raft.NewDiscardSnapshotStore(), t1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r1.Shutdown().Error() })

	cfg2 := raft.DefaultConfig()
	cfg2.LocalID = "node-2"
	cfg2.Logger = hclogzerolog.NewWithCustomNameField(log.Logger().With().Str("component", "raft").Str("node", "node-2").Logger(), "name")
	r2, err := raft.NewRaft(cfg2, &raft.MockFSM{}, raft.NewInmemStore(), raft.NewInmemStore(), raft.NewDiscardSnapshotStore(), t2)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r2.Shutdown().Error() })

	cfg3 := raft.DefaultConfig()
	cfg3.LocalID = "node-3"
	cfg3.Logger = hclogzerolog.NewWithCustomNameField(log.Logger().With().Str("component", "raft").Str("node", "node-3").Logger(), "name")
	r3, err := raft.NewRaft(cfg3, &raft.MockFSM{}, raft.NewInmemStore(), raft.NewInmemStore(), raft.NewDiscardSnapshotStore(), t3)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r3.Shutdown().Error() })

	configuration := raft.Configuration{
		Servers: []raft.Server{
			{ID: "node-1", Address: addr1},
			{ID: "node-2", Address: addr2},
			{ID: "node-3", Address: addr3},
		},
	}
	assert.NoError(t, r1.BootstrapCluster(configuration).Error())
	assert.NoError(t, r2.BootstrapCluster(configuration).Error())
	assert.NoError(t, r3.BootstrapCluster(configuration).Error())

	assert.Eventually(t, func() bool {
		return r1.Leader() != ""
	}, 10*time.Second, 100*time.Millisecond)
}
