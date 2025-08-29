package databroker

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type clusteredLeaderServer struct {
	local Server
}

func newClusteredLeaderServer(local Server) Server {
	return &clusteredLeaderServer{local: local}
}

func (srv *clusteredLeaderServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	return srv.local.AcquireLease(ctx, req)
}

func (srv *clusteredLeaderServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	return srv.local.Get(ctx, req)
}

func (srv *clusteredLeaderServer) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	return srv.local.List(ctx, req)
}

func (srv *clusteredLeaderServer) ListTypes(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	return srv.local.ListTypes(ctx, req)
}

func (srv *clusteredLeaderServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	return srv.local.Patch(ctx, req)
}

func (srv *clusteredLeaderServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	return srv.local.Put(ctx, req)
}

func (srv *clusteredLeaderServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	return srv.local.Query(ctx, req)
}

func (srv *clusteredLeaderServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	return srv.local.ReleaseLease(ctx, req)
}

func (srv *clusteredLeaderServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	return srv.local.RenewLease(ctx, req)
}

func (srv *clusteredLeaderServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	return srv.local.Report(ctx, req)
}

func (srv *clusteredLeaderServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	return srv.local.ServerInfo(ctx, req)
}

func (srv *clusteredLeaderServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
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

func (srv *clusteredLeaderServer) Stop()                                              {}
func (srv *clusteredLeaderServer) OnConfigChange(_ context.Context, _ *config.Config) {}
