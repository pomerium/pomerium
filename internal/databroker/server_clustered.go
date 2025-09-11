package databroker

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-cmp/cmp"
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

	registrypb.UnimplementedRegistryServer

	mu                   sync.RWMutex
	stopped              bool
	currentLeaderElector LeaderElector
	currentOptions       config.DataBrokerOptions
	currentServer        Server
}

// NewClusteredServer creates a new clustered server. A clustered server is
// either a follower, a leader, or in an erroring state.
func NewClusteredServer(tracerProvider oteltrace.TracerProvider, local Server) Server {
	srv := &clusteredServer{
		local:                local,
		clientManager:        NewClientManager(tracerProvider),
		currentLeaderElector: NewStaticLeaderElector(null.String{}),
		currentServer:        NewErroringServer(databrokerpb.ErrNotInitialized),
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

func (srv *clusteredServer) GetCheckpoint(ctx context.Context, req *databrokerpb.GetCheckpointRequest) (*databrokerpb.GetCheckpointResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.GetCheckpoint(ctx, req)
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

func (srv *clusteredServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ServerInfo(ctx, req)
}

func (srv *clusteredServer) SetCheckpoint(ctx context.Context, req *databrokerpb.SetCheckpointRequest) (*databrokerpb.SetCheckpointResponse, error) {
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

func (srv *clusteredServer) Stop() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.local.Stop()
	srv.currentLeaderElector.Stop()
	srv.currentLeaderElector = NewStaticLeaderElector(null.String{})
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

	// if no cluster settings are being used, don't start a leader elector
	if !srv.currentOptions.ClusterNodeID.IsValid() || len(srv.currentOptions.ClusterNodes) == 0 {
		srv.currentLeaderElector = NewStaticLeaderElector(null.String{})
		return
	}

	if srv.currentOptions.ClusterLeaderID.IsValid() {
		srv.currentLeaderElector = NewStaticLeaderElector(srv.currentOptions.ClusterLeaderID)
	} else {
		// for now just use the first cluster node
		srv.currentLeaderElector = NewStaticLeaderElector(null.StringFrom(srv.currentOptions.ClusterNodes[0].ID))
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
		srv.currentServer = NewErroringServer(databrokerpb.ErrNoClusterNodeID)
		return
	}

	// require a cluster node list
	if len(srv.currentOptions.ClusterNodes) == 0 {
		log.Info().Msg("databroker-clustered-server: no cluster nodes are defined")
		srv.currentServer = NewErroringServer(databrokerpb.ErrNoClusterNodes)
		return
	}

	// if the leader is is set, use that
	leaderID := srv.currentLeaderElector.ElectedLeaderID()
	if !leaderID.IsValid() {
		log.Info().Msg("databroker-clustered-server: cluster has no leader")
		srv.currentServer = NewErroringServer(databrokerpb.ErrClusterHasNoLeader)
		return
	}

	// find the leader url
	var leaderGRPCAddress null.String
	for _, n := range srv.currentOptions.ClusterNodes {
		if n.ID == leaderID.String {
			leaderGRPCAddress = null.StringFrom(n.GRPCAddress)
		}
	}
	if !leaderGRPCAddress.IsValid() {
		log.Info().Msg("databroker-clustered-server: cluster has no leader grpc address")
		srv.currentServer = NewErroringServer(databrokerpb.ErrNoClusterLeaderGRPCAddress)
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
		srv.currentServer = NewClusteredFollowerServer(srv.local, srv.clientManager.GetClient(leaderGRPCAddress.String))
	}
}

func dataBrokerOptionsAreEqual(o1, o2 config.DataBrokerOptions) bool {
	return cmp.Equal(o1, o2)
}
