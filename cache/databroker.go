package cache

import (
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A DataBrokerServer implements the data broker service interface.
type DataBrokerServer struct {
	*databroker.Server
}

// NewDataBrokerServer creates a new databroker service server.
func NewDataBrokerServer(grpcServer *grpc.Server, cfg *config.Config) *DataBrokerServer {
	srv := &DataBrokerServer{}
	srv.Server = databroker.New(srv.getOptions(cfg)...)
	databrokerpb.RegisterDataBrokerServiceServer(grpcServer, srv)
	return srv
}

// OnConfigChange updates the underlying databroker server whenever configuration is changed.
func (srv *DataBrokerServer) OnConfigChange(cfg *config.Config) {
	srv.UpdateConfig(srv.getOptions(cfg)...)
}

func (srv *DataBrokerServer) getOptions(cfg *config.Config) []databroker.ServerOption {
	return []databroker.ServerOption{
		databroker.WithSharedKey(cfg.Options.SharedKey),
		databroker.WithStorageType(cfg.Options.DataBrokerStorageType),
		databroker.WithStorageConnectionString(cfg.Options.DataBrokerStorageConnectionString),
		databroker.WithStorageCAFile(cfg.Options.DataBrokerStorageCAFile),
		databroker.WithStorageCertificate(cfg.Options.DataBrokerCertificate),
		databroker.WithStorageCertSkipVerify(cfg.Options.DataBrokerStorageCertSkipVerify),
	}
}
