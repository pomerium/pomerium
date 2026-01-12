package databroker

import (
	"context"
	"fmt"
	"sync"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker/raft"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/health"
)

type clusteredServer struct {
	telemetry     telemetry.Component
	local         Server
	clientManager *ClientManager
	streamLayer   raft.StreamLayer

	mu                   sync.RWMutex
	stopped              bool
	currentLeaderElector LeaderElector
	currentOptions       config.DataBrokerOptions
	currentServer        Server
}

type storageMetricAttributeSetter interface {
	SetStorageMetricAttributes(attrs ...attribute.KeyValue)
}

// NewClusteredServer creates a new clustered server. A clustered server is
// either a follower, a leader, or in an erroring state.
func NewClusteredServer(tracerProvider oteltrace.TracerProvider, local Server, cfg *config.Config) Server {
	srv := &clusteredServer{
		telemetry:      *telemetry.NewComponent(tracerProvider, zerolog.TraceLevel, "databroker-clustered-server"),
		local:          local,
		clientManager:  NewClientManager(tracerProvider),
		streamLayer:    raft.NewStreamLayer(tracerProvider),
		currentOptions: cfg.Options.DataBroker,
	}
	srv.local.OnConfigChange(context.Background(), cfg)
	srv.clientManager.OnConfigChange(context.Background(), cfg)
	srv.streamLayer.OnConfigChange(context.Background(), cfg)
	srv.updateLeaderElectorLocked()
	srv.updateServerLocked()
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

func (srv *clusteredServer) SetCheckpoint(ctx context.Context, req *databrokerpb.SetCheckpointRequest) (*databrokerpb.SetCheckpointResponse, error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.SetCheckpoint(ctx, req)
}

func (srv *clusteredServer) GetOptions(ctx context.Context, req *databrokerpb.GetOptionsRequest) (res *databrokerpb.GetOptionsResponse, err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.GetOptions(ctx, req)
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

// config methods

func (srv *clusteredServer) CreateKeyPair(ctx context.Context, req *connect.Request[configpb.CreateKeyPairRequest]) (res *connect.Response[configpb.CreateKeyPairResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.CreateKeyPair(ctx, req)
}

func (srv *clusteredServer) CreateNamespace(ctx context.Context, req *connect.Request[configpb.CreateNamespaceRequest]) (res *connect.Response[configpb.CreateNamespaceResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.CreateNamespace(ctx, req)
}

func (srv *clusteredServer) CreatePolicy(ctx context.Context, req *connect.Request[configpb.CreatePolicyRequest]) (res *connect.Response[configpb.CreatePolicyResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.CreatePolicy(ctx, req)
}

func (srv *clusteredServer) CreateRoute(ctx context.Context, req *connect.Request[configpb.CreateRouteRequest]) (res *connect.Response[configpb.CreateRouteResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.CreateRoute(ctx, req)
}

func (srv *clusteredServer) DeleteKeyPair(ctx context.Context, req *connect.Request[configpb.DeleteKeyPairRequest]) (res *connect.Response[configpb.DeleteKeyPairResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.DeleteKeyPair(ctx, req)
}

func (srv *clusteredServer) DeleteNamespace(ctx context.Context, req *connect.Request[configpb.DeleteNamespaceRequest]) (res *connect.Response[configpb.DeleteNamespaceResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.DeleteNamespace(ctx, req)
}

func (srv *clusteredServer) DeletePolicy(ctx context.Context, req *connect.Request[configpb.DeletePolicyRequest]) (res *connect.Response[configpb.DeletePolicyResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.DeletePolicy(ctx, req)
}

func (srv *clusteredServer) DeleteRoute(ctx context.Context, req *connect.Request[configpb.DeleteRouteRequest]) (res *connect.Response[configpb.DeleteRouteResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.DeleteRoute(ctx, req)
}

func (srv *clusteredServer) GetKeyPair(ctx context.Context, req *connect.Request[configpb.GetKeyPairRequest]) (res *connect.Response[configpb.GetKeyPairResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.GetKeyPair(ctx, req)
}

func (srv *clusteredServer) GetNamespace(ctx context.Context, req *connect.Request[configpb.GetNamespaceRequest]) (res *connect.Response[configpb.GetNamespaceResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.GetNamespace(ctx, req)
}

func (srv *clusteredServer) GetPolicy(ctx context.Context, req *connect.Request[configpb.GetPolicyRequest]) (res *connect.Response[configpb.GetPolicyResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.GetPolicy(ctx, req)
}

func (srv *clusteredServer) GetRoute(ctx context.Context, req *connect.Request[configpb.GetRouteRequest]) (res *connect.Response[configpb.GetRouteResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.GetRoute(ctx, req)
}

func (srv *clusteredServer) GetSettings(ctx context.Context, req *connect.Request[configpb.GetSettingsRequest]) (res *connect.Response[configpb.GetSettingsResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.GetSettings(ctx, req)
}

func (srv *clusteredServer) ListKeyPairs(ctx context.Context, req *connect.Request[configpb.ListKeyPairsRequest]) (res *connect.Response[configpb.ListKeyPairsResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ListKeyPairs(ctx, req)
}

func (srv *clusteredServer) ListNamespaces(ctx context.Context, req *connect.Request[configpb.ListNamespacesRequest]) (res *connect.Response[configpb.ListNamespacesResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ListNamespaces(ctx, req)
}

func (srv *clusteredServer) ListPolicies(ctx context.Context, req *connect.Request[configpb.ListPoliciesRequest]) (res *connect.Response[configpb.ListPoliciesResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ListPolicies(ctx, req)
}

func (srv *clusteredServer) ListRoutes(ctx context.Context, req *connect.Request[configpb.ListRoutesRequest]) (res *connect.Response[configpb.ListRoutesResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ListRoutes(ctx, req)
}

func (srv *clusteredServer) ListSettings(ctx context.Context, req *connect.Request[configpb.ListSettingsRequest]) (res *connect.Response[configpb.ListSettingsResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.ListSettings(ctx, req)
}

func (srv *clusteredServer) UpdateKeyPair(ctx context.Context, req *connect.Request[configpb.UpdateKeyPairRequest]) (res *connect.Response[configpb.UpdateKeyPairResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.UpdateKeyPair(ctx, req)
}

func (srv *clusteredServer) UpdateNamespace(ctx context.Context, req *connect.Request[configpb.UpdateNamespaceRequest]) (res *connect.Response[configpb.UpdateNamespaceResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.UpdateNamespace(ctx, req)
}

func (srv *clusteredServer) UpdatePolicy(ctx context.Context, req *connect.Request[configpb.UpdatePolicyRequest]) (res *connect.Response[configpb.UpdatePolicyResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.UpdatePolicy(ctx, req)
}

func (srv *clusteredServer) UpdateRoute(ctx context.Context, req *connect.Request[configpb.UpdateRouteRequest]) (res *connect.Response[configpb.UpdateRouteResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.UpdateRoute(ctx, req)
}

func (srv *clusteredServer) UpdateSettings(ctx context.Context, req *connect.Request[configpb.UpdateSettingsRequest]) (res *connect.Response[configpb.UpdateSettingsResponse], err error) {
	srv.mu.RLock()
	current := srv.currentServer
	srv.mu.RUnlock()
	return current.UpdateSettings(ctx, req)
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
	srv.streamLayer.OnConfigChange(ctx, cfg)

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
	ctx, op := srv.telemetry.Start(context.Background(), "UpdateLeader")
	defer op.Complete()

	if srv.currentLeaderElector != nil {
		srv.currentLeaderElector.Stop()
	}

	// if no cluster settings are being used, don't start a leader elector
	if !srv.currentOptions.ClusterNodeID.IsValid() || len(srv.currentOptions.ClusterNodes) == 0 {
		log.Ctx(ctx).Info().Msg("disabling leader election")
		srv.currentLeaderElector = NewStaticLeaderElector(null.String{})
		return
	}

	// if the cluster leader is set explicitly, use that
	if srv.currentOptions.ClusterLeaderID.IsValid() {
		log.Ctx(ctx).Info().Str("cluster-leader-id", srv.currentOptions.ClusterLeaderID.String).Msg("using configured leader")
		srv.currentLeaderElector = NewStaticLeaderElector(srv.currentOptions.ClusterLeaderID)
		return
	}

	// if there's a raft bind address, use raft to determine the leader
	if srv.currentOptions.RaftBindAddress.IsValid() {
		log.Ctx(ctx).Info().Msg("using raft leader elector")
		srv.currentLeaderElector = NewRaftLeaderElector(srv.telemetry.GetTracerProvider(), srv.streamLayer, srv.currentOptions, srv.OnLeaderChange)
		return
	}

	// fallback to the first cluster node if raft isn't available
	log.Ctx(ctx).Info().Msg("using first cluster node as leader")
	srv.currentLeaderElector = NewStaticLeaderElector(null.StringFrom(srv.currentOptions.ClusterNodes[0].ID))
}

func (srv *clusteredServer) updateServerLocked() {
	ctx, op := srv.telemetry.Start(context.Background(), "UpdateServer")
	defer op.Complete()

	if setter, ok := srv.local.(storageMetricAttributeSetter); ok {
		setter.SetStorageMetricAttributes()
	}

	if srv.currentServer != nil {
		srv.currentServer.Stop()
	}

	// if no cluster settings are being used, just use local
	if !srv.currentOptions.ClusterNodeID.IsValid() || len(srv.currentOptions.ClusterNodes) == 0 {
		health.ReportRunning(health.DatabrokerCluster, health.StrAttr("member", "leader"))
		log.Ctx(ctx).Info().Msg("node is not part of a cluster")
		srv.currentServer = withoutStop(srv.local)
		return
	}

	// require a cluster node id
	nodeID := srv.currentOptions.ClusterNodeID
	if !nodeID.IsValid() {
		log.Ctx(ctx).Error().Msg("node has no id")
		srv.currentServer = NewErroringServer(databrokerpb.ErrNoClusterNodeID)
		return
	}

	if setter, ok := srv.local.(storageMetricAttributeSetter); ok {
		setter.SetStorageMetricAttributes(attribute.String("node-id", nodeID.String))
	}

	ctx = log.Ctx(ctx).With().Str("cluster-node-id", nodeID.String).Logger().WithContext(ctx)

	// require a cluster node list
	if len(srv.currentOptions.ClusterNodes) == 0 {
		log.Ctx(ctx).Error().Msg("no cluster nodes are defined")
		srv.currentServer = NewErroringServer(databrokerpb.ErrNoClusterNodes)
		return
	}

	// get the elected leader
	leaderID := srv.currentLeaderElector.ElectedLeaderID()
	if !leaderID.IsValid() {
		log.Ctx(ctx).Error().Msg("cluster has no leader")
		srv.currentServer = NewErroringServer(databrokerpb.ErrClusterHasNoLeader)
		return
	}

	ctx = log.Ctx(ctx).With().Str("cluster-leader-id", leaderID.String).Logger().WithContext(ctx)

	// find the leader grpc address
	var leaderGRPCAddress null.String
	for _, n := range srv.currentOptions.ClusterNodes {
		if n.ID == leaderID.String {
			leaderGRPCAddress = null.StringFrom(n.GRPCAddress)
		}
	}
	if !leaderGRPCAddress.IsValid() {
		log.Ctx(ctx).Error().Msg("cluster has no leader grpc address")
		srv.currentServer = NewErroringServer(databrokerpb.ErrNoClusterLeaderGRPCAddress)
		return
	}

	// if we're the leader, act as leader, otherwise act as follower
	if nodeID == leaderID {
		log.Ctx(ctx).Info().Msg("node is the leader")
		srv.currentServer = NewClusteredLeaderServer(srv.local)
	} else {
		log.Ctx(ctx).Info().Msg("node is a follower")
		srv.currentServer = NewClusteredFollowerServer(srv.telemetry.GetTracerProvider(), srv.local, srv.clientManager.GetClient(leaderGRPCAddress.String))
	}
}

func dataBrokerOptionsAreEqual(o1, o2 config.DataBrokerOptions) bool {
	return cmp.Equal(o1, o2)
}
