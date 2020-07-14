package cache

import (
	"google.golang.org/grpc"

	internal_databroker "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A DataBrokerServer implements the data broker service interface.
type DataBrokerServer struct {
	databroker.DataBrokerServiceServer
}

// NewDataBrokerServer creates a new databroker service server.
func NewDataBrokerServer(grpcServer *grpc.Server) *DataBrokerServer {
	srv := &DataBrokerServer{DataBrokerServiceServer: internal_databroker.New()}
	databroker.RegisterDataBrokerServiceServer(grpcServer, srv)
	return srv
}
