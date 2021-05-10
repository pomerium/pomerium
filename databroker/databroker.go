// Package databroker contains the databroker service.
package databroker

import (
	"context"
	"sync/atomic"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// A dataBrokerServer implements the data broker service interface.
type dataBrokerServer struct {
	server    *databroker.Server
	sharedKey atomic.Value
}

// newDataBrokerServer creates a new databroker service server.
func newDataBrokerServer(cfg *config.Config) *dataBrokerServer {
	srv := &dataBrokerServer{}
	srv.server = databroker.New(srv.getOptions(cfg)...)
	srv.setKey(cfg)
	return srv
}

// OnConfigChange updates the underlying databroker server whenever configuration is changed.
func (srv *dataBrokerServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.server.UpdateConfig(srv.getOptions(cfg)...)
	srv.setKey(cfg)
}

func (srv *dataBrokerServer) getOptions(cfg *config.Config) []databroker.ServerOption {
	cert, _ := cfg.Options.GetDataBrokerCertificate()
	return []databroker.ServerOption{
		databroker.WithGetSharedKey(cfg.Options.GetSharedKey),
		databroker.WithStorageType(cfg.Options.DataBrokerStorageType),
		databroker.WithStorageConnectionString(cfg.Options.DataBrokerStorageConnectionString),
		databroker.WithStorageCAFile(cfg.Options.DataBrokerStorageCAFile),
		databroker.WithStorageCertificate(cert),
		databroker.WithStorageCertSkipVerify(cfg.Options.DataBrokerStorageCertSkipVerify),
	}
}

func (srv *dataBrokerServer) setKey(cfg *config.Config) {
	bs, _ := cfg.Options.GetSharedKey()
	if bs == nil {
		bs = make([]byte, 0)
	}
	srv.sharedKey.Store(bs)
}

// Databroker functions

func (srv *dataBrokerServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.AcquireLease(ctx, req)
}

func (srv *dataBrokerServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.Get(ctx, req)
}

func (srv *dataBrokerServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.Query(ctx, req)
}

func (srv *dataBrokerServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.Put(ctx, req)
}

func (srv *dataBrokerServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.ReleaseLease(ctx, req)
}

func (srv *dataBrokerServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.RenewLease(ctx, req)
}

func (srv *dataBrokerServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.SetOptions(ctx, req)
}

func (srv *dataBrokerServer) Sync(req *databrokerpb.SyncRequest, stream databrokerpb.DataBrokerService_SyncServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load().([]byte)); err != nil {
		return err
	}
	return srv.server.Sync(req, stream)
}

func (srv *dataBrokerServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load().([]byte)); err != nil {
		return err
	}
	return srv.server.SyncLatest(req, stream)
}

// Registry functions

func (srv *dataBrokerServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.Report(ctx, req)
}

func (srv *dataBrokerServer) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.List(ctx, req)
}

func (srv *dataBrokerServer) Watch(req *registrypb.ListRequest, stream registrypb.Registry_WatchServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load().([]byte)); err != nil {
		return err
	}
	return srv.server.Watch(req, stream)
}
