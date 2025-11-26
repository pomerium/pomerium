package databroker

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
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

func (srv *erroringServer) Stop()                                              {}
func (srv *erroringServer) OnConfigChange(_ context.Context, _ *config.Config) {}
