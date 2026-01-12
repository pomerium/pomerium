package databroker

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/health"
)

type clusteredLeaderServer struct {
	local    Server
	onChange signal.Signal

	cancel context.CancelCauseFunc
}

// NewClusteredLeaderServer creates a new clustered leader databroker server.
// A clustered leader server implements the server interface via a local
// backend server.
func NewClusteredLeaderServer(local Server) Server {
	health.ReportRunning(health.DatabrokerCluster, health.StrAttr("member", "leader"))
	srv := &clusteredLeaderServer{
		local:    local,
		onChange: *signal.New(),
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	srv.cancel = cancel
	go srv.run(ctx)
	return srv
}

func (srv *clusteredLeaderServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (res *databrokerpb.AcquireLeaseResponse, err error) {
	return srv.local.AcquireLease(ctx, req)
}

func (srv *clusteredLeaderServer) Clear(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ClearResponse, err error) {
	defer srv.onChange.Broadcast(ctx)
	return srv.local.Clear(ctx, req)
}

func (srv *clusteredLeaderServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (res *databrokerpb.GetResponse, err error) {
	return srv.local.Get(ctx, req)
}

func (srv *clusteredLeaderServer) GetCheckpoint(ctx context.Context, req *databrokerpb.GetCheckpointRequest) (res *databrokerpb.GetCheckpointResponse, err error) {
	res, err = srv.local.GetCheckpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	res.IsLeader = true
	return res, nil
}

func (srv *clusteredLeaderServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	return srv.local.List(ctx, req)
}

func (srv *clusteredLeaderServer) ListTypes(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ListTypesResponse, err error) {
	return srv.local.ListTypes(ctx, req)
}

func (srv *clusteredLeaderServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (res *databrokerpb.PatchResponse, err error) {
	defer srv.onChange.Broadcast(ctx)
	return srv.local.Patch(ctx, req)
}

func (srv *clusteredLeaderServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (res *databrokerpb.PutResponse, err error) {
	defer srv.onChange.Broadcast(ctx)
	return srv.local.Put(ctx, req)
}

func (srv *clusteredLeaderServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (res *databrokerpb.QueryResponse, err error) {
	return srv.local.Query(ctx, req)
}

func (srv *clusteredLeaderServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (res *emptypb.Empty, err error) {
	return srv.local.ReleaseLease(ctx, req)
}

func (srv *clusteredLeaderServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (res *emptypb.Empty, err error) {
	return srv.local.RenewLease(ctx, req)
}

func (srv *clusteredLeaderServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	return srv.local.Report(ctx, req)
}

func (srv *clusteredLeaderServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	return srv.local.ServerInfo(ctx, req)
}

func (srv *clusteredLeaderServer) SetCheckpoint(_ context.Context, _ *databrokerpb.SetCheckpointRequest) (*databrokerpb.SetCheckpointResponse, error) {
	return nil, databrokerpb.ErrSetCheckpointNotSupported
}

func (srv *clusteredLeaderServer) GetOptions(ctx context.Context, req *databrokerpb.GetOptionsRequest) (res *databrokerpb.GetOptionsResponse, err error) {
	return srv.local.GetOptions(ctx, req)
}

func (srv *clusteredLeaderServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (res *databrokerpb.SetOptionsResponse, err error) {
	defer srv.onChange.Broadcast(ctx)
	return srv.local.SetOptions(ctx, req)
}

func (srv *clusteredLeaderServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return srv.local.Sync(req, stream)
}

func (srv *clusteredLeaderServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return srv.local.SyncLatest(req, stream)
}

func (srv *clusteredLeaderServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return srv.local.Watch(req, stream)
}

// config methods

func (srv *clusteredLeaderServer) CreateKeyPair(ctx context.Context, req *connect.Request[configpb.CreateKeyPairRequest]) (res *connect.Response[configpb.CreateKeyPairResponse], err error) {
	return srv.local.CreateKeyPair(ctx, req)
}

func (srv *clusteredLeaderServer) CreateNamespace(ctx context.Context, req *connect.Request[configpb.CreateNamespaceRequest]) (res *connect.Response[configpb.CreateNamespaceResponse], err error) {
	return srv.local.CreateNamespace(ctx, req)
}

func (srv *clusteredLeaderServer) CreatePolicy(ctx context.Context, req *connect.Request[configpb.CreatePolicyRequest]) (res *connect.Response[configpb.CreatePolicyResponse], err error) {
	return srv.local.CreatePolicy(ctx, req)
}

func (srv *clusteredLeaderServer) CreateRoute(ctx context.Context, req *connect.Request[configpb.CreateRouteRequest]) (res *connect.Response[configpb.CreateRouteResponse], err error) {
	return srv.local.CreateRoute(ctx, req)
}

func (srv *clusteredLeaderServer) DeleteKeyPair(ctx context.Context, req *connect.Request[configpb.DeleteKeyPairRequest]) (res *connect.Response[configpb.DeleteKeyPairResponse], err error) {
	return srv.local.DeleteKeyPair(ctx, req)
}

func (srv *clusteredLeaderServer) DeleteNamespace(ctx context.Context, req *connect.Request[configpb.DeleteNamespaceRequest]) (res *connect.Response[configpb.DeleteNamespaceResponse], err error) {
	return srv.local.DeleteNamespace(ctx, req)
}

func (srv *clusteredLeaderServer) DeletePolicy(ctx context.Context, req *connect.Request[configpb.DeletePolicyRequest]) (res *connect.Response[configpb.DeletePolicyResponse], err error) {
	return srv.local.DeletePolicy(ctx, req)
}

func (srv *clusteredLeaderServer) DeleteRoute(ctx context.Context, req *connect.Request[configpb.DeleteRouteRequest]) (res *connect.Response[configpb.DeleteRouteResponse], err error) {
	return srv.local.DeleteRoute(ctx, req)
}

func (srv *clusteredLeaderServer) GetKeyPair(ctx context.Context, req *connect.Request[configpb.GetKeyPairRequest]) (res *connect.Response[configpb.GetKeyPairResponse], err error) {
	return srv.local.GetKeyPair(ctx, req)
}

func (srv *clusteredLeaderServer) GetNamespace(ctx context.Context, req *connect.Request[configpb.GetNamespaceRequest]) (res *connect.Response[configpb.GetNamespaceResponse], err error) {
	return srv.local.GetNamespace(ctx, req)
}

func (srv *clusteredLeaderServer) GetPolicy(ctx context.Context, req *connect.Request[configpb.GetPolicyRequest]) (res *connect.Response[configpb.GetPolicyResponse], err error) {
	return srv.local.GetPolicy(ctx, req)
}

func (srv *clusteredLeaderServer) GetRoute(ctx context.Context, req *connect.Request[configpb.GetRouteRequest]) (res *connect.Response[configpb.GetRouteResponse], err error) {
	return srv.local.GetRoute(ctx, req)
}

func (srv *clusteredLeaderServer) GetSettings(ctx context.Context, req *connect.Request[configpb.GetSettingsRequest]) (res *connect.Response[configpb.GetSettingsResponse], err error) {
	return srv.local.GetSettings(ctx, req)
}

func (srv *clusteredLeaderServer) ListKeyPairs(ctx context.Context, req *connect.Request[configpb.ListKeyPairsRequest]) (res *connect.Response[configpb.ListKeyPairsResponse], err error) {
	return srv.local.ListKeyPairs(ctx, req)
}

func (srv *clusteredLeaderServer) ListNamespaces(ctx context.Context, req *connect.Request[configpb.ListNamespacesRequest]) (res *connect.Response[configpb.ListNamespacesResponse], err error) {
	return srv.local.ListNamespaces(ctx, req)
}

func (srv *clusteredLeaderServer) ListPolicies(ctx context.Context, req *connect.Request[configpb.ListPoliciesRequest]) (res *connect.Response[configpb.ListPoliciesResponse], err error) {
	return srv.local.ListPolicies(ctx, req)
}

func (srv *clusteredLeaderServer) ListRoutes(ctx context.Context, req *connect.Request[configpb.ListRoutesRequest]) (res *connect.Response[configpb.ListRoutesResponse], err error) {
	return srv.local.ListRoutes(ctx, req)
}

func (srv *clusteredLeaderServer) ListSettings(ctx context.Context, req *connect.Request[configpb.ListSettingsRequest]) (res *connect.Response[configpb.ListSettingsResponse], err error) {
	return srv.local.ListSettings(ctx, req)
}

func (srv *clusteredLeaderServer) UpdateKeyPair(ctx context.Context, req *connect.Request[configpb.UpdateKeyPairRequest]) (res *connect.Response[configpb.UpdateKeyPairResponse], err error) {
	return srv.local.UpdateKeyPair(ctx, req)
}

func (srv *clusteredLeaderServer) UpdateNamespace(ctx context.Context, req *connect.Request[configpb.UpdateNamespaceRequest]) (res *connect.Response[configpb.UpdateNamespaceResponse], err error) {
	return srv.local.UpdateNamespace(ctx, req)
}

func (srv *clusteredLeaderServer) UpdatePolicy(ctx context.Context, req *connect.Request[configpb.UpdatePolicyRequest]) (res *connect.Response[configpb.UpdatePolicyResponse], err error) {
	return srv.local.UpdatePolicy(ctx, req)
}

func (srv *clusteredLeaderServer) UpdateRoute(ctx context.Context, req *connect.Request[configpb.UpdateRouteRequest]) (res *connect.Response[configpb.UpdateRouteResponse], err error) {
	return srv.local.UpdateRoute(ctx, req)
}

func (srv *clusteredLeaderServer) UpdateSettings(ctx context.Context, req *connect.Request[configpb.UpdateSettingsRequest]) (res *connect.Response[configpb.UpdateSettingsResponse], err error) {
	return srv.local.UpdateSettings(ctx, req)
}

func (srv *clusteredLeaderServer) Stop() {
	srv.cancel(nil)
}

func (srv *clusteredLeaderServer) OnConfigChange(_ context.Context, _ *config.Config) {}

func (srv *clusteredLeaderServer) run(ctx context.Context) {
	ch := srv.onChange.Bind()
	for {
		// retrieve the current server info
		res, err := srv.local.ServerInfo(ctx, new(emptypb.Empty))
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker-clustered-leader-server: error retrieving current server info")
			continue
		}

		// set the checkpoint to the current server version and latest record version
		_, err = srv.local.SetCheckpoint(ctx, &databrokerpb.SetCheckpointRequest{
			Checkpoint: &databrokerpb.Checkpoint{
				ServerVersion: res.GetServerVersion(),
				RecordVersion: res.GetLatestRecordVersion(),
			},
		})
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker-clustered-leader-server: error updating checkpoint")
			continue
		}

		// wait for a change
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
	}
}
