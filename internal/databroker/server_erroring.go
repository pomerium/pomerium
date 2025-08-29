package databroker

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
)

type erroringServer struct {
	err error
}

// NewErroringServer creates a server that returns an error for all gRPC calls.
func NewErroringServer(err error) Server {
	return &erroringServer{err: err}
}

func (srv *erroringServer) AcquireLease(_ context.Context, _ *databroker.AcquireLeaseRequest) (*databroker.AcquireLeaseResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Get(_ context.Context, _ *databroker.GetRequest) (*databroker.GetResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) List(_ context.Context, _ *registry.ListRequest) (*registry.ServiceList, error) {
	return nil, srv.err
}

func (srv *erroringServer) ListTypes(_ context.Context, _ *emptypb.Empty) (*databroker.ListTypesResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Patch(_ context.Context, _ *databroker.PatchRequest) (*databroker.PatchResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Put(_ context.Context, _ *databroker.PutRequest) (*databroker.PutResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Query(_ context.Context, _ *databroker.QueryRequest) (*databroker.QueryResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) ReleaseLease(_ context.Context, _ *databroker.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	return nil, srv.err
}

func (srv *erroringServer) RenewLease(_ context.Context, _ *databroker.RenewLeaseRequest) (*emptypb.Empty, error) {
	return nil, srv.err
}

func (srv *erroringServer) Report(_ context.Context, _ *registry.RegisterRequest) (*registry.RegisterResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) ServerInfo(_ context.Context, _ *emptypb.Empty) (*databroker.ServerInfoResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) SetOptions(_ context.Context, _ *databroker.SetOptionsRequest) (*databroker.SetOptionsResponse, error) {
	return nil, srv.err
}

func (srv *erroringServer) Sync(_ *databroker.SyncRequest, _ grpc.ServerStreamingServer[databroker.SyncResponse]) error {
	return srv.err
}

func (srv *erroringServer) SyncLatest(_ *databroker.SyncLatestRequest, _ grpc.ServerStreamingServer[databroker.SyncLatestResponse]) error {
	return srv.err
}

func (srv *erroringServer) Watch(_ *registry.ListRequest, _ grpc.ServerStreamingServer[registry.ServiceList]) error {
	return srv.err
}

func (srv *erroringServer) Stop() {}

func (srv *erroringServer) OnConfigChange(_ context.Context, _ *config.Config) {}
