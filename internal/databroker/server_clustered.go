package databroker

import (
	"context"
	"fmt"
	"sync"

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

	serverLock       sync.RWMutex
	serverStopped    bool
	currentServer    Server
	currentNodeID    string
	currentLeaderID  string
	currentLeaderURL string
}

// NewClusteredServer creates a new clustered server. A clustered server is
// either a follower, a leader, or in an erroring state.
func NewClusteredServer(tracerProvider oteltrace.TracerProvider, local Server) Server {
	srv := &clusteredServer{
		local:         local,
		clientManager: NewClientManager(tracerProvider),
		currentServer: NewErroringServer(fmt.Errorf("not initialized")),
	}
	return srv
}

func (srv *clusteredServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.AcquireLease(ctx, req)
}

func (srv *clusteredServer) Clear(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ClearResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.Clear(ctx, req)
}

func (srv *clusteredServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.Get(ctx, req)
}

func (srv *clusteredServer) ListTypes(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.ListTypes(ctx, req)
}

func (srv *clusteredServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.Patch(ctx, req)
}

func (srv *clusteredServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.Put(ctx, req)
}

func (srv *clusteredServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.Query(ctx, req)
}

func (srv *clusteredServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.ReleaseLease(ctx, req)
}

func (srv *clusteredServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.RenewLease(ctx, req)
}

func (srv *clusteredServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.ServerInfo(ctx, req)
}

func (srv *clusteredServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.SetOptions(ctx, req)
}

func (srv *clusteredServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.Sync(req, stream)
}

func (srv *clusteredServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	srv.serverLock.RLock()
	current := srv.currentServer
	srv.serverLock.RUnlock()
	return current.SyncLatest(req, stream)
}

func (srv *clusteredServer) Stop() {
	srv.serverLock.Lock()
	defer srv.serverLock.Unlock()

	srv.currentServer.Stop()
	srv.currentServer = NewErroringServer(fmt.Errorf("clustered server stopped"))
	srv.serverStopped = true
}

func (srv *clusteredServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.updateClientManager(ctx, cfg)
	srv.updateServer(ctx, cfg)
}

func (srv *clusteredServer) updateClientManager(ctx context.Context, cfg *config.Config) {
	srv.clientManager.OnConfigChange(ctx, cfg)
}

func (srv *clusteredServer) updateServer(ctx context.Context, cfg *config.Config) {
	srv.serverLock.Lock()
	defer srv.serverLock.Unlock()

	// stopped, so just ignore
	if srv.serverStopped {
		return
	}

	if len(cfg.Options.DataBroker.ClusterNodes) == 0 {
		srv.currentServer = NewErroringServer(fmt.Errorf("no cluster nodes defined"))
		return
	}

	if !cfg.Options.DataBroker.ClusterNodeID.IsValid() {
		srv.currentServer = NewErroringServer(fmt.Errorf("no cluster node id defined"))
		return
	}
	nodeID := cfg.Options.DataBroker.ClusterNodeID.String

	found := false
	for _, n := range cfg.Options.DataBroker.ClusterNodes {
		found = found || n.ID == nodeID
	}
	if !found {
		srv.currentServer = NewErroringServer(fmt.Errorf("cluster node not found in cluster node list"))
		return
	}

	var leaderID, leaderURL string
	if cfg.Options.DataBroker.ClusterLeaderID.IsValid() {
		leaderID = cfg.Options.DataBroker.ClusterLeaderID.String
	} else {
		leaderID = cfg.Options.DataBroker.ClusterNodes[0].ID
	}
	for _, n := range cfg.Options.DataBroker.ClusterNodes {
		if n.ID == leaderID {
			leaderURL = n.URL
		}
	}
	if leaderURL == "" {
		srv.currentServer = NewErroringServer(fmt.Errorf("cluster has no leader url"))
		return
	}

	// if nothing has changed, just return
	if srv.currentNodeID == nodeID &&
		srv.currentLeaderID == leaderID &&
		srv.currentLeaderURL == leaderURL {
		return
	}
	srv.currentNodeID = nodeID
	srv.currentLeaderID = leaderID
	srv.currentLeaderURL = leaderURL
	srv.currentServer.Stop()

	if nodeID == leaderID {
		log.Ctx(ctx).Info().
			Str("cluster-node-id", nodeID).
			Str("cluster-leader-id", leaderID).
			Msg("databroker-clustered-server: node is the leader")
		srv.currentServer = NewClusteredLeaderServer(srv.local)
	} else {
		log.Ctx(ctx).Info().
			Str("cluster-node-id", nodeID).
			Str("cluster-leader-id", leaderID).
			Msg("databroker-clustered-server: node is a follower")
		srv.currentServer = NewClusteredFollowerServer(srv.local, srv.clientManager.GetClient(leaderURL))
	}
}
