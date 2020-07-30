package cache

import (
	"encoding/base64"
	"fmt"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	internal_databroker "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A DataBrokerServer implements the data broker service interface.
type DataBrokerServer struct {
	databroker.DataBrokerServiceServer
}

// NewDataBrokerServer creates a new databroker service server.
func NewDataBrokerServer(grpcServer *grpc.Server, opts config.Options) (*DataBrokerServer, error) {
	key, err := base64.StdEncoding.DecodeString(opts.SharedKey)
	if err != nil || len(key) != cryptutil.DefaultKeySize {
		return nil, fmt.Errorf("shared key is required and must be %d bytes long", cryptutil.DefaultKeySize)
	}
	internalSrv := internal_databroker.New(
		internal_databroker.WithSecret(key),
		internal_databroker.WithStorageType(opts.DataBrokerStorageType),
		internal_databroker.WithStorageConnectionString(opts.DataBrokerStorageConnectionString),
	)
	srv := &DataBrokerServer{DataBrokerServiceServer: internalSrv}
	databroker.RegisterDataBrokerServiceServer(grpcServer, srv)
	return srv, nil
}
