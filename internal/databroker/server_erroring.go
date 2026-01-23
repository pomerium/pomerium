package databroker

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/health"
)

type erroringServer struct {
	err error
}

// NewErroringServer creates a new Server that returns an error for all databroker and registry methods.
func NewErroringServer(err error) Server {
	health.ReportError(health.DatabrokerCluster, err, health.StrAttr("member", "unknown"))
	return &erroringServer{err: err}
}

func (srv *erroringServer) AcquireLease(_ context.Context, _ *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Clear(_ context.Context, _ *emptypb.Empty) (*databrokerpb.ClearResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Get(_ context.Context, _ *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) GetCheckpoint(_ context.Context, _ *databrokerpb.GetCheckpointRequest) (*databrokerpb.GetCheckpointResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) List(_ context.Context, _ *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	return nil, srv.err
}

func (srv *erroringServer) ListTypes(_ context.Context, _ *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Patch(_ context.Context, _ *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Put(_ context.Context, _ *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Query(_ context.Context, _ *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) ReleaseLease(_ context.Context, _ *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	return nil, srv.err
}

func (srv *erroringServer) RenewLease(_ context.Context, _ *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	return nil, srv.err
}

func (srv *erroringServer) Report(_ context.Context, _ *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) ServerInfo(_ context.Context, _ *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) SetCheckpoint(_ context.Context, _ *databrokerpb.SetCheckpointRequest) (*databrokerpb.SetCheckpointResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) GetOptions(_ context.Context, _ *databrokerpb.GetOptionsRequest) (*databrokerpb.GetOptionsResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) SetOptions(_ context.Context, _ *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Sync(_ *databrokerpb.SyncRequest, _ grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return srv.err
}

func (srv *erroringServer) SyncLatest(_ *databrokerpb.SyncLatestRequest, _ grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return srv.err
}

func (srv *erroringServer) Watch(_ *registrypb.ListRequest, _ grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return srv.err
}

// config methods

func (srv *erroringServer) CreateKeyPair(_ context.Context, _ *connect.Request[configpb.CreateKeyPairRequest]) (*connect.Response[configpb.CreateKeyPairResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) CreatePolicy(_ context.Context, _ *connect.Request[configpb.CreatePolicyRequest]) (*connect.Response[configpb.CreatePolicyResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) CreateRoute(_ context.Context, _ *connect.Request[configpb.CreateRouteRequest]) (*connect.Response[configpb.CreateRouteResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) DeleteKeyPair(_ context.Context, _ *connect.Request[configpb.DeleteKeyPairRequest]) (*connect.Response[configpb.DeleteKeyPairResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) DeletePolicy(_ context.Context, _ *connect.Request[configpb.DeletePolicyRequest]) (*connect.Response[configpb.DeletePolicyResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) DeleteRoute(_ context.Context, _ *connect.Request[configpb.DeleteRouteRequest]) (*connect.Response[configpb.DeleteRouteResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) GetKeyPair(_ context.Context, _ *connect.Request[configpb.GetKeyPairRequest]) (*connect.Response[configpb.GetKeyPairResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) GetPolicy(_ context.Context, _ *connect.Request[configpb.GetPolicyRequest]) (*connect.Response[configpb.GetPolicyResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) GetRoute(_ context.Context, _ *connect.Request[configpb.GetRouteRequest]) (*connect.Response[configpb.GetRouteResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) GetSettings(_ context.Context, _ *connect.Request[configpb.GetSettingsRequest]) (*connect.Response[configpb.GetSettingsResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) ListKeyPairs(_ context.Context, _ *connect.Request[configpb.ListKeyPairsRequest]) (*connect.Response[configpb.ListKeyPairsResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) ListPolicies(_ context.Context, _ *connect.Request[configpb.ListPoliciesRequest]) (*connect.Response[configpb.ListPoliciesResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) ListRoutes(_ context.Context, _ *connect.Request[configpb.ListRoutesRequest]) (*connect.Response[configpb.ListRoutesResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) ListSettings(_ context.Context, _ *connect.Request[configpb.ListSettingsRequest]) (*connect.Response[configpb.ListSettingsResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) UpdateKeyPair(_ context.Context, _ *connect.Request[configpb.UpdateKeyPairRequest]) (*connect.Response[configpb.UpdateKeyPairResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) UpdatePolicy(_ context.Context, _ *connect.Request[configpb.UpdatePolicyRequest]) (*connect.Response[configpb.UpdatePolicyResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) UpdateRoute(_ context.Context, _ *connect.Request[configpb.UpdateRouteRequest]) (*connect.Response[configpb.UpdateRouteResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) UpdateSettings(_ context.Context, _ *connect.Request[configpb.UpdateSettingsRequest]) (*connect.Response[configpb.UpdateSettingsResponse], error) {
	return nil, srv.err
}

func (srv *erroringServer) Stop()                                              {}
func (srv *erroringServer) OnConfigChange(_ context.Context, _ *config.Config) {}
