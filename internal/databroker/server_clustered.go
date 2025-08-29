package databroker

import (
	"context"
	"slices"
	"sync"

	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v9"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type clusteredServer struct {
	telemetry     telemetry.Component
	local         Server
	clientManager *ClientManager

	mu             sync.RWMutex
	current        Server
	previousNodeID null.String
	previousNodes  config.DataBrokerClusterNodes
}

// NewClusteredServer creates a new clustered server. A clustered server is
// a member of a cluster of databroker nodes.
func NewClusteredServer(tracerProvider oteltrace.TracerProvider, local Server, cfg *config.Config) Server {
	srv := &clusteredServer{
		telemetry:     *telemetry.NewComponent(tracerProvider, zerolog.DebugLevel, "databroker-clustered-server"),
		clientManager: NewClientManager(tracerProvider),
		local:         local,
	}
	srv.updateLocked(context.Background(), cfg)
	return srv
}

func (srv *clusteredServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.AcquireLease(ctx, req)
}

func (srv *clusteredServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.Get(ctx, req)
}

func (srv *clusteredServer) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.List(ctx, req)
}

func (srv *clusteredServer) ListTypes(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.ListTypes(ctx, req)
}

func (srv *clusteredServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.Patch(ctx, req)
}

func (srv *clusteredServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.Put(ctx, req)
}

func (srv *clusteredServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.Query(ctx, req)
}

func (srv *clusteredServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.ReleaseLease(ctx, req)
}

func (srv *clusteredServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.RenewLease(ctx, req)
}

func (srv *clusteredServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.Report(ctx, req)
}

func (srv *clusteredServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.ServerInfo(ctx, req)
}

func (srv *clusteredServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.SetOptions(ctx, req)
}

func (srv *clusteredServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.Sync(req, stream)
}

func (srv *clusteredServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.SyncLatest(req, stream)
}

func (srv *clusteredServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	srv.mu.RLock()
	s := srv.current
	srv.mu.RUnlock()
	return s.Watch(req, stream)
}

func (srv *clusteredServer) Stop() {
	srv.mu.Lock()
	srv.current.Stop()
	srv.mu.Unlock()
}

func (srv *clusteredServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.local.OnConfigChange(ctx, cfg)
	srv.clientManager.OnConfigChange(ctx, cfg)
	srv.mu.Lock()
	srv.updateLocked(ctx, cfg)
	srv.current.OnConfigChange(ctx, cfg)
	srv.mu.Unlock()
}

func (srv *clusteredServer) updateLocked(ctx context.Context, cfg *config.Config) {
	ctx, op := srv.telemetry.Start(ctx, "update")
	defer op.Complete()

	// if nothing changed in the config, just return
	if srv.current != nil &&
		srv.previousNodeID == cfg.Options.DataBroker.ClusterNodeID &&
		slices.Equal(srv.previousNodes, cfg.Options.DataBroker.ClusterNodes) {
		return
	}
	srv.previousNodeID = cfg.Options.DataBroker.ClusterNodeID
	srv.previousNodes = slices.Clone(cfg.Options.DataBroker.ClusterNodes)

	// stop the current server
	if srv.current != nil {
		srv.current.Stop()
	}

	// this node doesn't have an id
	if !cfg.Options.DataBroker.ClusterNodeID.IsValid() {
		srv.current = NewErroringServer(databrokerpb.ErrServerNotAClusterMember)
		return
	}

	lookup := map[string]string{}
	maxNodeID := ""
	for _, node := range cfg.Options.DataBroker.ClusterNodes {
		lookup[node.ID] = node.URL
		maxNodeID = max(node.ID, maxNodeID)
	}

	// we didn't find this node in the cluster topology
	if _, ok := lookup[cfg.Options.DataBroker.ClusterNodeID.String]; !ok {
		srv.current = NewErroringServer(databrokerpb.ErrServerNotAClusterMember)
		return
	}

	// TODO: implement leader election
	if cfg.Options.DataBroker.ClusterNodeID.String == maxNodeID {
		log.Ctx(ctx).Info().
			Str("node-id", cfg.Options.DataBroker.ClusterNodeID.String).
			Msg("node is the leader")
		srv.current = newClusteredLeaderServer(srv.local)
	} else {
		log.Ctx(ctx).Info().
			Str("node-id", cfg.Options.DataBroker.ClusterNodeID.String).
			Str("leader-node-id", maxNodeID).
			Str("leader-node-url", lookup[maxNodeID]).
			Msg("node is a follower")
		srv.current = newClusteredFollowerServer(srv.telemetry.GetTracerProvider(), srv.local, srv.clientManager.GetClient(lookup[maxNodeID]))
	}
}
