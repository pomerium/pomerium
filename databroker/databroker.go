// Package databroker contains the databroker service.
package databroker

import (
	"context"
	"encoding/base64"
	"sync/atomic"

	"google.golang.org/protobuf/types/known/emptypb"

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

// newDataBrokerServer creates a new databroker service server.
func newDataBrokerServer(cfg *config.Config) *dataBrokerServer {
	srv := &dataBrokerServer{}
	srv.server = databroker.New(srv.getOptions(cfg)...)
	srv.setKey(cfg)
	return srv
}

// OnConfigChange updates the underlying databroker server whenever configuration is changed.
func (srv *dataBrokerServer) OnConfigChange(cfg *config.Config) {
	srv.server.UpdateConfig(srv.getOptions(cfg)...)
	srv.setKey(cfg)
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

func (srv *dataBrokerServer) setKey(cfg *config.Config) {
	bs, _ := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	if bs == nil {
		bs = make([]byte, 0)
	}
	srv.sharedKey.Store(bs)
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

func (srv *dataBrokerServer) Sync(req *databrokerpb.SyncRequest, stream databrokerpb.DataBrokerService_SyncServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load().([]byte)); err != nil {
		return err
	}
	return srv.server.Sync(req, stream)
}

func (srv *dataBrokerServer) SyncLatest(req *emptypb.Empty, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load().([]byte)); err != nil {
		return err
	}
	return srv.server.SyncLatest(req, stream)
}
