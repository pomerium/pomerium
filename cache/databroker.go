package cache

import (
	"context"
	"encoding/base64"
	"sync/atomic"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// A dataBrokerServer implements the data broker service interface.
type dataBrokerServer struct {
	server    *databroker.Server
	sharedKey atomic.Value
}

// NewDataBrokerServer creates a new databroker service server.
func NewDataBrokerServer(cfg *config.Config) *dataBrokerServer {
	srv := &dataBrokerServer{}
	srv.server = databroker.New(srv.getOptions(cfg)...)

	bs, _ := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	srv.sharedKey.Store(bs)

	return srv
}

// OnConfigChange updates the underlying databroker server whenever configuration is changed.
func (srv *dataBrokerServer) OnConfigChange(cfg *config.Config) {
	srv.server.UpdateConfig(srv.getOptions(cfg)...)

	bs, _ := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	srv.sharedKey.Store(bs)
}

func (srv *dataBrokerServer) getOptions(cfg *config.Config) []databroker.ServerOption {
	return []databroker.ServerOption{
		databroker.WithSharedKey(cfg.Options.SharedKey),
		databroker.WithStorageType(cfg.Options.DataBrokerStorageType),
		databroker.WithStorageConnectionString(cfg.Options.DataBrokerStorageConnectionString),
		databroker.WithStorageCAFile(cfg.Options.DataBrokerStorageCAFile),
		databroker.WithStorageCertificate(cfg.Options.DataBrokerCertificate),
		databroker.WithStorageCertSkipVerify(cfg.Options.DataBrokerStorageCertSkipVerify),
	}
}

func (srv *dataBrokerServer) Delete(ctx context.Context, req *databrokerpb.DeleteRequest) (*empty.Empty, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.Delete(ctx, req)
}

func (srv *dataBrokerServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.Get(ctx, req)
}

func (srv *dataBrokerServer) GetAll(ctx context.Context, req *databrokerpb.GetAllRequest) (*databrokerpb.GetAllResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.GetAll(ctx, req)
}

func (srv *dataBrokerServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.Query(ctx, req)
}

func (srv *dataBrokerServer) Set(ctx context.Context, req *databrokerpb.SetRequest) (*databrokerpb.SetResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.Set(ctx, req)
}

func (srv *dataBrokerServer) Sync(req *databrokerpb.SyncRequest, stream databrokerpb.DataBrokerService_SyncServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load().([]byte)); err != nil {
		return err
	}
	return srv.server.Sync(req, stream)
}

func (srv *dataBrokerServer) GetTypes(ctx context.Context, req *empty.Empty) (*databrokerpb.GetTypesResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load().([]byte)); err != nil {
		return nil, err
	}
	return srv.server.GetTypes(ctx, req)
}

func (srv *dataBrokerServer) SyncTypes(req *empty.Empty, stream databrokerpb.DataBrokerService_SyncTypesServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load().([]byte)); err != nil {
		return err
	}
	return srv.server.SyncTypes(req, stream)
}
