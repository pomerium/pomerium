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
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type clusteredServer struct {
	local         Server
	clientManager *ClientManager

	registrypb.UnimplementedRegistryServer

	mu             sync.RWMutex
	serverStopped  bool
	currentOptions config.DataBrokerOptions
	currentServer  Server
}

// NewClusteredServer creates a new clustered server. A clustered server is
// either a follower, a leader, or in an erroring state.
func NewClusteredServer(tracerProvider oteltrace.TracerProvider, local Server) Server {
	srv := &clusteredServer{
		local:         local,
		clientManager: NewClientManager(tracerProvider),
	}
	srv.initializeServerLocked()
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
	srv.currentServer.Stop()
	srv.currentServer = NewErroringServer(fmt.Errorf("clustered server stopped"))
	srv.serverStopped = true
}

func (srv *clusteredServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.clientManager.OnConfigChange(ctx, cfg)
	srv.local.OnConfigChange(ctx, cfg)

	srv.mu.Lock()
	defer srv.mu.Unlock()

	// stopped, so just ignore
	if srv.serverStopped {
		return
	}

	if dataBrokerOptionsAreEqual(cfg.Options.DataBroker, srv.currentOptions) {
		// nothing has changed so just return
		return
	}
	srv.currentOptions = cfg.Options.DataBroker

	// stop the current server
	srv.currentServer.Stop()

	srv.initializeServerLocked()
}

func (srv *clusteredServer) initializeServerLocked() {
	// if no cluster settings are being used, just act as leader
	if !srv.currentOptions.ClusterNodeID.IsValid() || len(srv.currentOptions.ClusterNodes) == 0 {
		srv.currentServer = NewClusteredLeaderServer(srv.local)
		return
	}

	// require a cluster node id
	nodeID := srv.currentOptions.ClusterNodeID
	if !nodeID.IsValid() {
		srv.currentServer = NewErroringServer(fmt.Errorf("no cluster node id defined"))
		return
	}

	// require a cluster node list
	if len(srv.currentOptions.ClusterNodes) == 0 {
		srv.currentServer = NewErroringServer(fmt.Errorf("no cluster nodes defined"))
		return
	}

	// if the leader is is set, use that
	leaderID := srv.currentOptions.ClusterLeaderID
	if !leaderID.IsValid() {
		// just pick the first node for now
		leaderID = null.StringFrom(srv.currentOptions.ClusterNodes[0].ID)
	}

	// find the leader url
	leaderURL := null.NewString("", false)
	for _, n := range srv.currentOptions.ClusterNodes {
		if n.ID == leaderID.String {
			leaderURL = null.StringFrom(n.URL)
		}
	}
	if !leaderURL.IsValid() {
		srv.currentServer = NewErroringServer(fmt.Errorf("no cluster leader url defined"))
		return
	}

	// if we're the leader, act as leader, otherwise act as follower
	if nodeID == leaderID {
		srv.currentServer = NewClusteredLeaderServer(srv.local)
	} else {
		srv.currentServer = NewClusteredFollowerServer(srv.local, srv.clientManager.GetClient(leaderURL.String))
	}
}

func dataBrokerOptionsAreEqual(o1, o2 config.DataBrokerOptions) bool {
	return cmp.Equal(o1, o2)
}
