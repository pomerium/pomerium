package cache

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	internal_databroker "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/log"
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

	caCertPool := x509.NewCertPool()
	if caCert, err := ioutil.ReadFile(opts.DataBrokerStorageCAFile); err == nil {
		caCertPool.AppendCertsFromPEM(caCert)
	} else {
		log.Warn().Err(err).Msg("failed to read databroker CA file")
	}
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{*opts.DataBrokerCertificate},
		// nolint: gosec
		InsecureSkipVerify: opts.DataBrokerStorageCertSkipVerify,
	}

	internalSrv := internal_databroker.New(
		internal_databroker.WithSecret(key),
		internal_databroker.WithStorageType(opts.DataBrokerStorageType),
		internal_databroker.WithStorageConnectionString(opts.DataBrokerStorageConnectionString),
		internal_databroker.WithStorageTLSConfig(tlsConfig),
	)
	srv := &DataBrokerServer{DataBrokerServiceServer: internalSrv}
	databroker.RegisterDataBrokerServiceServer(grpcServer, srv)
	return srv, nil
}
