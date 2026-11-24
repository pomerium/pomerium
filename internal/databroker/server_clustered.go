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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker/raft"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/contextutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/health"
)

var (
	errClusteredServerStopped = status.Error(codes.Canceled, "stopped")
	errClusteredServerChanged = status.Error(codes.Unavailable, "server changed")
)

type clusteredServer struct {
	telemetry     telemetry.Component
	local         Server
	clientManager *ClientManager
	streamLayer   raft.StreamLayer

	mu                   sync.Mutex
	stopped              bool
	currentLeaderElector LeaderElector
	currentOptions       config.DataBrokerOptions
	currentServer        Server
	activeWG             sync.WaitGroup
	activeCtx            context.Context
	activeCancel         context.CancelCauseFunc
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
	srv.activeCtx, srv.activeCancel = context.WithCancelCause(context.Background())
	srv.local.OnConfigChange(context.Background(), cfg)
	srv.clientManager.OnConfigChange(context.Background(), cfg)
	srv.streamLayer.OnConfigChange(context.Background(), cfg)
	srv.updateLeaderElectorLocked()
	srv.updateServerLocked()
	return srv
}

func (srv *clusteredServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (res *databrokerpb.AcquireLeaseResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.AcquireLease(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) Clear(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ClearResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.Clear(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (res *databrokerpb.GetResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.Get(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) GetCheckpoint(ctx context.Context, req *databrokerpb.GetCheckpointRequest) (res *databrokerpb.GetCheckpointResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.GetCheckpoint(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.List(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ListTypes(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ListTypesResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ListTypes(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (res *databrokerpb.PatchResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.Patch(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (res *databrokerpb.PutResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.Put(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (res *databrokerpb.QueryResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.Query(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (res *emptypb.Empty, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ReleaseLease(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (res *emptypb.Empty, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.RenewLease(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.Report(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ServerInfo(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) SetCheckpoint(ctx context.Context, req *databrokerpb.SetCheckpointRequest) (res *databrokerpb.SetCheckpointResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.SetCheckpoint(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) GetOptions(ctx context.Context, req *databrokerpb.GetOptionsRequest) (res *databrokerpb.GetOptionsResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.GetOptions(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (res *databrokerpb.SetOptionsResponse, err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.SetOptions(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return srv.do(stream.Context(), func(ctx context.Context, current Server) error {
		return grpcutil.HandleServerStreamingServerWithContext(ctx, stream, func(stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
			return current.Sync(req, stream)
		})
	})
}

func (srv *clusteredServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return srv.do(stream.Context(), func(ctx context.Context, current Server) error {
		return grpcutil.HandleServerStreamingServerWithContext(ctx, stream, func(stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
			return current.SyncLatest(req, stream)
		})
	})
}

func (srv *clusteredServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return srv.do(stream.Context(), func(ctx context.Context, current Server) error {
		return grpcutil.HandleServerStreamingServerWithContext(ctx, stream, func(stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
			return current.Watch(req, stream)
		})
	})
}

// config methods

func (srv *clusteredServer) CreateKeyPair(ctx context.Context, req *connect.Request[configpb.CreateKeyPairRequest]) (res *connect.Response[configpb.CreateKeyPairResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.CreateKeyPair(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) CreatePolicy(ctx context.Context, req *connect.Request[configpb.CreatePolicyRequest]) (res *connect.Response[configpb.CreatePolicyResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.CreatePolicy(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) CreateRoute(ctx context.Context, req *connect.Request[configpb.CreateRouteRequest]) (res *connect.Response[configpb.CreateRouteResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.CreateRoute(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) CreateServiceAccount(ctx context.Context, req *connect.Request[configpb.CreateServiceAccountRequest]) (res *connect.Response[configpb.CreateServiceAccountResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.CreateServiceAccount(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) DeleteKeyPair(ctx context.Context, req *connect.Request[configpb.DeleteKeyPairRequest]) (res *connect.Response[configpb.DeleteKeyPairResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.DeleteKeyPair(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) DeletePolicy(ctx context.Context, req *connect.Request[configpb.DeletePolicyRequest]) (res *connect.Response[configpb.DeletePolicyResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.DeletePolicy(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) DeleteRoute(ctx context.Context, req *connect.Request[configpb.DeleteRouteRequest]) (res *connect.Response[configpb.DeleteRouteResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.DeleteRoute(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) DeleteServiceAccount(ctx context.Context, req *connect.Request[configpb.DeleteServiceAccountRequest]) (res *connect.Response[configpb.DeleteServiceAccountResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.DeleteServiceAccount(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) GetKeyPair(ctx context.Context, req *connect.Request[configpb.GetKeyPairRequest]) (res *connect.Response[configpb.GetKeyPairResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.GetKeyPair(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) GetPolicy(ctx context.Context, req *connect.Request[configpb.GetPolicyRequest]) (res *connect.Response[configpb.GetPolicyResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.GetPolicy(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) GetRoute(ctx context.Context, req *connect.Request[configpb.GetRouteRequest]) (res *connect.Response[configpb.GetRouteResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.GetRoute(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) GetServerInfo(ctx context.Context, req *connect.Request[configpb.GetServerInfoRequest]) (res *connect.Response[configpb.GetServerInfoResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.GetServerInfo(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) GetServiceAccount(ctx context.Context, req *connect.Request[configpb.GetServiceAccountRequest]) (res *connect.Response[configpb.GetServiceAccountResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.GetServiceAccount(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) GetSettings(ctx context.Context, req *connect.Request[configpb.GetSettingsRequest]) (res *connect.Response[configpb.GetSettingsResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.GetSettings(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ListAvailableLogFields(ctx context.Context, req *connect.Request[configpb.ListAvailableLogFieldsRequest]) (res *connect.Response[configpb.ListAvailableLogFieldsResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ListAvailableLogFields(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ListKeyPairs(ctx context.Context, req *connect.Request[configpb.ListKeyPairsRequest]) (res *connect.Response[configpb.ListKeyPairsResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ListKeyPairs(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ListPolicies(ctx context.Context, req *connect.Request[configpb.ListPoliciesRequest]) (res *connect.Response[configpb.ListPoliciesResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ListPolicies(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ListRoutes(ctx context.Context, req *connect.Request[configpb.ListRoutesRequest]) (res *connect.Response[configpb.ListRoutesResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ListRoutes(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ListServiceAccounts(ctx context.Context, req *connect.Request[configpb.ListServiceAccountsRequest]) (res *connect.Response[configpb.ListServiceAccountsResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ListServiceAccounts(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) ListSettings(ctx context.Context, req *connect.Request[configpb.ListSettingsRequest]) (res *connect.Response[configpb.ListSettingsResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.ListSettings(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) UpdateKeyPair(ctx context.Context, req *connect.Request[configpb.UpdateKeyPairRequest]) (res *connect.Response[configpb.UpdateKeyPairResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.UpdateKeyPair(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) UpdatePolicy(ctx context.Context, req *connect.Request[configpb.UpdatePolicyRequest]) (res *connect.Response[configpb.UpdatePolicyResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.UpdatePolicy(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) UpdateRoute(ctx context.Context, req *connect.Request[configpb.UpdateRouteRequest]) (res *connect.Response[configpb.UpdateRouteResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.UpdateRoute(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) UpdateServiceAccount(ctx context.Context, req *connect.Request[configpb.UpdateServiceAccountRequest]) (res *connect.Response[configpb.UpdateServiceAccountResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.UpdateServiceAccount(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) UpdateSettings(ctx context.Context, req *connect.Request[configpb.UpdateSettingsRequest]) (res *connect.Response[configpb.UpdateSettingsResponse], err error) {
	err = srv.do(ctx, func(ctx context.Context, current Server) error {
		var err error
		res, err = current.UpdateSettings(ctx, req)
		return err
	})
	return res, err
}

func (srv *clusteredServer) Stop() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// cancel and wait for any in-flight operations before stopping anything
	srv.activeCancel(errClusteredServerStopped)
	srv.activeWG.Wait()
	srv.currentLeaderElector.Stop()
	srv.currentLeaderElector = NewStaticLeaderElector(null.String{})
	srv.currentServer.Stop()
	srv.currentServer = NewErroringServer(fmt.Errorf("clustered server stopped"))
	// the current server may wrap the local server, so stop it last
	srv.local.Stop()
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

func (srv *clusteredServer) do(
	ctx context.Context,
	fn func(ctx context.Context, current Server) error,
) error {
	srv.mu.Lock()
	current := srv.currentServer
	ctx, cancel := contextutil.Merge(ctx, srv.activeCtx)
	defer cancel(nil)
	srv.activeWG.Add(1)
	defer srv.activeWG.Done()
	srv.mu.Unlock()
	return fn(ctx, current)
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
		// cancel and wait for any in-flight operations before stopping the current server
		srv.activeCancel(errClusteredServerChanged)
		srv.activeWG.Wait()
		srv.currentServer.Stop()
		srv.activeCtx, srv.activeCancel = context.WithCancelCause(context.Background())
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
