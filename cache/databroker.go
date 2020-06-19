package cache

import (
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/databroker/memory"
	"github.com/pomerium/pomerium/internal/grpc/databroker"
)

// A DataBrokerServer implements the data broker service interface.
type DataBrokerServer struct {
	databroker.DataBrokerServiceServer
}

// NewDataBrokerServer creates a new databroker service server.
func NewDataBrokerServer(grpcServer *grpc.Server) *DataBrokerServer {
	srv := &DataBrokerServer{
		// just wrap the in-memory data broker server
		DataBrokerServiceServer: memory.New(),
	}
	databroker.RegisterDataBrokerServiceServer(grpcServer, srv)
	return srv
}
