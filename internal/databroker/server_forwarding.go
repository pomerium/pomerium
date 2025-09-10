package databroker

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
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

func (srv *forwardingServer) GetCheckpoint(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.Checkpoint, err error) {
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

func (srv *forwardingServer) SetCheckpoint(ctx context.Context, req *databrokerpb.Checkpoint) (res *emptypb.Empty, err error) {
	return grpcutil.ForwardUnary(ctx, srv.forwarder, databrokerpb.NewCheckpointServiceClient(srv.cc).SetCheckpoint, req)
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

func (srv *forwardingServer) Stop()                                              {}
func (srv *forwardingServer) OnConfigChange(_ context.Context, _ *config.Config) {}
