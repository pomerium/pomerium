package cache

import (
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	internal_databroker "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A DataBrokerServer implements the data broker service interface.
type DataBrokerServer struct {
	databroker.DataBrokerServiceServer
}

// NewDataBrokerServer creates a new databroker service server.
func NewDataBrokerServer(grpcServer *grpc.Server, opts config.Options) *DataBrokerServer {
	internalSrv := internal_databroker.New(
		internal_databroker.WithStorageType(opts.DataBrokerBackendStorageType),
		internal_databroker.WithStorageConnectionString(opts.DataBrokerBackendStorageConnectionString),
	)
	srv := &DataBrokerServer{DataBrokerServiceServer: internalSrv}
	databroker.RegisterDataBrokerServiceServer(grpcServer, srv)
	return srv
}
