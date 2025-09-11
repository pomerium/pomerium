package databroker

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/raft"
	"github.com/volatiletech/null/v9"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type clusteredServer struct {
	local         Server
	clientManager *ClientManager
	raftServer    databrokerpb.RaftServer

	mu                   sync.RWMutex
	stopped              bool
	currentLeaderElector LeaderElector
	currentOptions       config.DataBrokerOptions
	currentRaftServer    databrokerpb.RaftServer
	currentServer        Server
}

// NewClusteredServer creates a new clustered server. A clustered server is
// either a follower, a leader, or in an erroring state.
func NewClusteredServer(tracerProvider oteltrace.TracerProvider, local Server,
) Server {
	srv := &clusteredServer{
		local:         local,
		clientManager: NewClientManager(tracerProvider),

		currentLeaderElector: NewStaticLeaderElector(null.NewString("", false)),
		currentRaftServer:    databrokerpb.NewRaftServer("databroker-clustered-server"),
		currentServer:        NewErroringServer(fmt.Errorf("not initialized")),
	}
	return srv
}

func (srv *clusteredServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.AcquireLease(ctx, req)
}

func (srv *clusteredServer) Clear(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ClearResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.Clear(ctx, req)
}

func (srv *clusteredServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.Get(ctx, req)
}

func (srv *clusteredServer) GetCheckpoint(ctx context.Context, req *emptypb.Empty) (*databrokerpb.Checkpoint, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.GetCheckpoint(ctx, req)
}

func (srv *clusteredServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.List(ctx, req)
}

func (srv *clusteredServer) ListTypes(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ListTypes(ctx, req)
}

func (srv *clusteredServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.Patch(ctx, req)
}

func (srv *clusteredServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.Put(ctx, req)
}

func (srv *clusteredServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.Query(ctx, req)
}

func (srv *clusteredServer) Raft(stream grpc.BidiStreamingServer[databrokerpb.RaftRequest, databrokerpb.RaftResponse]) error {
	srv.mu.RLock()
	current := srv.currentRaftServer
	srv.mu.RUnlock()
	return current.ServeRaft(stream)
}

func (srv *clusteredServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ReleaseLease(ctx, req)
}

func (srv *clusteredServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.RenewLease(ctx, req)
}

func (srv *clusteredServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.Report(ctx, req)
}

func (srv *clusteredServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ServerInfo(ctx, req)
}

func (srv *clusteredServer) SetCheckpoint(ctx context.Context, req *databrokerpb.Checkpoint) (*emptypb.Empty, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.SetCheckpoint(ctx, req)
}

func (srv *clusteredServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.SetOptions(ctx, req)
}

func (srv *clusteredServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.Sync(req, stream)
}

func (srv *clusteredServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.SyncLatest(req, stream)
}

func (srv *clusteredServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.Watch(req, stream)
}

func (srv *clusteredServer) Stop() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.local.Stop()
	srv.currentLeaderElector.Stop()
	srv.currentLeaderElector = NewStaticLeaderElector(null.NewString("", false))
	srv.currentServer.Stop()
	srv.currentServer = NewErroringServer(fmt.Errorf("clustered server stopped"))
	srv.stopped = true
}

func (srv *clusteredServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.clientManager.OnConfigChange(ctx, cfg)
	srv.local.OnConfigChange(ctx, cfg)

	srv.mu.Lock()
	defer srv.mu.Unlock()

	// stopped, so just ignore
	if srv.stopped {
		return
	}

	if dataBrokerOptionsAreEqual(cfg.Options.DataBroker, srv.currentOptions) {
		// nothing has changed so just return
		return
	}
	srv.currentOptions = cfg.Options.DataBroker

	srv.updateLeaderElectorLocked()
	srv.updateServerLocked()
}

func (srv *clusteredServer) OnLeaderChange() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// stopped, so just ignore
	if srv.stopped {
		return
	}

	srv.updateServerLocked()
}

func (srv *clusteredServer) updateLeaderElectorLocked() {
	srv.currentLeaderElector.Stop()
	srv.currentRaftServer.Stop()

	// if no cluster settings are being used, don't start a leader elector
	if !srv.currentOptions.ClusterNodeID.IsValid() || len(srv.currentOptions.ClusterNodes) == 0 {
		srv.currentLeaderElector = NewStaticLeaderElector(null.String{})
		return
	}

	nodeID := srv.currentOptions.ClusterNodeID
	var grpcAddress null.String
	for _, n := range srv.currentOptions.ClusterNodes {
		if n.ID == nodeID.String {
			grpcAddress = null.StringFrom(n.GRPCAddress)
		}
	}

	if srv.currentOptions.ClusterLeaderID.IsValid() {
		log.Info().Msgf("databroker-clustered-server: using static leader elector: %s", srv.currentOptions.ClusterLeaderID.String)
		srv.currentLeaderElector = NewStaticLeaderElector(srv.currentOptions.ClusterLeaderID)
	} else {
		log.Info().Msg("databroker-clustered-server: using raft leader elector")
		srv.currentRaftServer = databrokerpb.NewRaftServer(raft.ServerAddress(grpcAddress.String))
		srv.currentLeaderElector = NewRaftLeaderElector(srv.currentOptions, srv.currentRaftServer, srv.clientManager, srv.OnLeaderChange)
	}
}

func (srv *clusteredServer) updateServerLocked() {
	srv.currentServer.Stop()

	// if no cluster settings are being used, just act as leader
	if !srv.currentOptions.ClusterNodeID.IsValid() || len(srv.currentOptions.ClusterNodes) == 0 {
		log.Info().Msg("databroker-clustered-server: node is not part of a cluster")
		srv.currentServer = NewClusteredLeaderServer(srv.local)
		return
	}

	// require a cluster node id
	nodeID := srv.currentOptions.ClusterNodeID
	if !nodeID.IsValid() {
		log.Info().Msg("databroker-clustered-server: node has no id")
		srv.currentServer = NewErroringServer(fmt.Errorf("no cluster node id defined"))
		return
	}

	// require a cluster node list
	if len(srv.currentOptions.ClusterNodes) == 0 {
		log.Info().Msg("databroker-clustered-server: no cluster nodes are defined")
		srv.currentServer = NewErroringServer(fmt.Errorf("no cluster nodes defined"))
		return
	}

	// if the leader is is set, use that
	leaderID := srv.currentLeaderElector.ElectedLeaderID()
	if !leaderID.IsValid() {
		log.Info().Msg("databroker-clustered-server: cluster has no leader")
		srv.currentServer = NewErroringServer(fmt.Errorf("cluster has no leader"))
		return
	}

	// find the leader url
	var leaderURL null.String
	for _, n := range srv.currentOptions.ClusterNodes {
		if n.ID == leaderID.String {
			leaderURL = null.StringFrom(n.URL)
		}
	}
	if !leaderURL.IsValid() {
		log.Info().Msg("databroker-clustered-server: cluster has no leader url")
		srv.currentServer = NewErroringServer(fmt.Errorf("no cluster leader url defined"))
		return
	}

	// if we're the leader, act as leader, otherwise act as follower
	if nodeID == leaderID {
		log.Info().
			Str("cluster-node-id", nodeID.String).
			Str("cluster-leader-id", leaderID.String).
			Msg("databroker-clustered-server: node is the leader")
		srv.currentServer = NewClusteredLeaderServer(srv.local)
	} else {
		log.Info().
			Str("cluster-node-id", nodeID.String).
			Str("cluster-leader-id", leaderID.String).
			Msg("databroker-clustered-server: node is a follower")
		srv.currentServer = NewClusteredFollowerServer(srv.local, srv.clientManager.GetClient(leaderURL.String))
	}
}

func dataBrokerOptionsAreEqual(o1, o2 config.DataBrokerOptions) bool {
	return cmp.Equal(o1, o2)
}
