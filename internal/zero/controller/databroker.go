package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func (c *controller) InitDatabrokerClient(ctx context.Context, cfg *config.Config) error {
	conn, err := c.newDataBrokerConnection(ctx, cfg)
	if err != nil {
		return fmt.Errorf("databroker connection: %w", err)
	}
	c.databrokerClient = databroker.NewDataBrokerServiceClient(conn)
	return nil
}

// GetDataBrokerServiceClient implements the databroker.Leaser interface.
func (c *controller) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return c.databrokerClient
}

func (c *controller) newDataBrokerConnection(ctx context.Context, cfg *config.Config) (*grpc.ClientConn, error) {
	sharedSecret, err := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	if err != nil {
		return nil, fmt.Errorf("decode shared_secret: %w", err)
	}

	return grpcutil.NewGRPCClientConn(ctx, &grpcutil.Options{
		Address: &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort("localhost", cfg.GRPCPort),
		},
		ServiceName:    "databroker",
		SignedJWTKey:   sharedSecret,
		RequestTimeout: c.cfg.databrokerRequestTimeout,
	})
}
