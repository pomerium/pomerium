package cache

import (
	"github.com/pomerium/pomerium/internal/databroker/memory"
	"github.com/pomerium/pomerium/internal/grpc/databroker"
)

// A DataBrokerServer implements the data broker service interface.
type DataBrokerServer struct {
	databroker.DataBrokerServiceServer
}

// NewDataBrokerServer creates a new databroker service server.
func NewDataBrokerServer() *DataBrokerServer {
	return &DataBrokerServer{
		// just wrap the in-memory data broker server
		DataBrokerServiceServer: memory.New(),
	}
}
