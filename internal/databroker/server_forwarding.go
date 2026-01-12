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
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type forwardingServer struct {
	cc        grpc.ClientConnInterface
	forwarder grpcutil.Forwarder
}

// NewForwardingServer creates a new server that forwards all requests to
// another server.
func NewForwardingServer(cc grpc.ClientConnInterface) Server {
	srv := &forwardingServer{
		cc:        cc,
		forwarder: grpcutil.NewForwarder(),
	}
	return srv
}

func (srv *forwardingServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (res *databrokerpb.AcquireLeaseResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).AcquireLease, req)
}

func (srv *forwardingServer) Clear(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ClearResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).Clear, req)
}

func (srv *forwardingServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (res *databrokerpb.GetResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).Get, req)
}

func (srv *forwardingServer) GetCheckpoint(ctx context.Context, req *databrokerpb.GetCheckpointRequest) (res *databrokerpb.GetCheckpointResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewCheckpointServiceClient(srv.cc).GetCheckpoint, req)
}

func (srv *forwardingServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, registrypb.NewRegistryClient(srv.cc).List, req)
}

func (srv *forwardingServer) ListTypes(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ListTypesResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).ListTypes, req)
}

func (srv *forwardingServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (res *databrokerpb.PatchResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).Patch, req)
}

func (srv *forwardingServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (res *databrokerpb.PutResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).Put, req)
}

func (srv *forwardingServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (res *databrokerpb.QueryResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).Query, req)
}

func (srv *forwardingServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (res *emptypb.Empty, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).ReleaseLease, req)
}

func (srv *forwardingServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (res *emptypb.Empty, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).RenewLease, req)
}

func (srv *forwardingServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, registrypb.NewRegistryClient(srv.cc).Report, req)
}

func (srv *forwardingServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).ServerInfo, req)
}

func (srv *forwardingServer) SetCheckpoint(ctx context.Context, req *databrokerpb.SetCheckpointRequest) (res *databrokerpb.SetCheckpointResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewCheckpointServiceClient(srv.cc).SetCheckpoint, req)
}

func (srv *forwardingServer) GetOptions(ctx context.Context, req *databrokerpb.GetOptionsRequest) (res *databrokerpb.GetOptionsResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).GetOptions, req)
}

func (srv *forwardingServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (res *databrokerpb.SetOptionsResponse, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewDataBrokerServiceClient(srv.cc).SetOptions, req)
}

func (srv *forwardingServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return grpcutil.ForwardStream(srv.forwarder, stream, databrokerpb.NewDataBrokerServiceClient(srv.cc).Sync, req)
}

func (srv *forwardingServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return grpcutil.ForwardStream(srv.forwarder, stream, databrokerpb.NewDataBrokerServiceClient(srv.cc).SyncLatest, req)
}

func (srv *forwardingServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return grpcutil.ForwardStream(srv.forwarder, stream, registrypb.NewRegistryClient(srv.cc).Watch, req)
}

// config methods

func (srv *forwardingServer) CreateKeyPair(ctx context.Context, req *connect.Request[configpb.CreateKeyPairRequest]) (res *connect.Response[configpb.CreateKeyPairResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).CreateKeyPair, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) CreateNamespace(ctx context.Context, req *connect.Request[configpb.CreateNamespaceRequest]) (res *connect.Response[configpb.CreateNamespaceResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).CreateNamespace, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) CreatePolicy(ctx context.Context, req *connect.Request[configpb.CreatePolicyRequest]) (res *connect.Response[configpb.CreatePolicyResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).CreatePolicy, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) CreateRoute(ctx context.Context, req *connect.Request[configpb.CreateRouteRequest]) (res *connect.Response[configpb.CreateRouteResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).CreateRoute, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) DeleteKeyPair(ctx context.Context, req *connect.Request[configpb.DeleteKeyPairRequest]) (res *connect.Response[configpb.DeleteKeyPairResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).DeleteKeyPair, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) DeleteNamespace(ctx context.Context, req *connect.Request[configpb.DeleteNamespaceRequest]) (res *connect.Response[configpb.DeleteNamespaceResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).DeleteNamespace, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) DeletePolicy(ctx context.Context, req *connect.Request[configpb.DeletePolicyRequest]) (res *connect.Response[configpb.DeletePolicyResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).DeletePolicy, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) DeleteRoute(ctx context.Context, req *connect.Request[configpb.DeleteRouteRequest]) (res *connect.Response[configpb.DeleteRouteResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).DeleteRoute, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) GetKeyPair(ctx context.Context, req *connect.Request[configpb.GetKeyPairRequest]) (res *connect.Response[configpb.GetKeyPairResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).GetKeyPair, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) GetNamespace(ctx context.Context, req *connect.Request[configpb.GetNamespaceRequest]) (res *connect.Response[configpb.GetNamespaceResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).GetNamespace, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) GetPolicy(ctx context.Context, req *connect.Request[configpb.GetPolicyRequest]) (res *connect.Response[configpb.GetPolicyResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).GetPolicy, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) GetRoute(ctx context.Context, req *connect.Request[configpb.GetRouteRequest]) (res *connect.Response[configpb.GetRouteResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).GetRoute, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) GetSettings(ctx context.Context, req *connect.Request[configpb.GetSettingsRequest]) (res *connect.Response[configpb.GetSettingsResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).GetSettings, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) ListKeyPairs(ctx context.Context, req *connect.Request[configpb.ListKeyPairsRequest]) (res *connect.Response[configpb.ListKeyPairsResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).ListKeyPairs, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) ListNamespaces(ctx context.Context, req *connect.Request[configpb.ListNamespacesRequest]) (res *connect.Response[configpb.ListNamespacesResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).ListNamespaces, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) ListPolicies(ctx context.Context, req *connect.Request[configpb.ListPoliciesRequest]) (res *connect.Response[configpb.ListPoliciesResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).ListPolicies, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) ListRoutes(ctx context.Context, req *connect.Request[configpb.ListRoutesRequest]) (res *connect.Response[configpb.ListRoutesResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).ListRoutes, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) ListSettings(ctx context.Context, req *connect.Request[configpb.ListSettingsRequest]) (res *connect.Response[configpb.ListSettingsResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).ListSettings, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) UpdateKeyPair(ctx context.Context, req *connect.Request[configpb.UpdateKeyPairRequest]) (res *connect.Response[configpb.UpdateKeyPairResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).UpdateKeyPair, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) UpdateNamespace(ctx context.Context, req *connect.Request[configpb.UpdateNamespaceRequest]) (res *connect.Response[configpb.UpdateNamespaceResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).UpdateNamespace, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) UpdatePolicy(ctx context.Context, req *connect.Request[configpb.UpdatePolicyRequest]) (res *connect.Response[configpb.UpdatePolicyResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).UpdatePolicy, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) UpdateRoute(ctx context.Context, req *connect.Request[configpb.UpdateRouteRequest]) (res *connect.Response[configpb.UpdateRouteResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).UpdateRoute, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) UpdateSettings(ctx context.Context, req *connect.Request[configpb.UpdateSettingsRequest]) (res *connect.Response[configpb.UpdateSettingsResponse], err error) {
	m, err := grpcutil.ForwardUnary(ctx, srv.forwarder, configpb.NewConfigServiceClient(srv.cc).UpdateSettings, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(m), nil
}

func (srv *forwardingServer) Stop()                                              {}
func (srv *forwardingServer) OnConfigChange(_ context.Context, _ *config.Config) {}
