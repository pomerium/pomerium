package databroker

import (
	"context"

	"github.com/pomerium/pomerium/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type clusteredServer struct {
	databrokerpb.UnimplementedDataBrokerServiceServer
	registrypb.UnimplementedRegistryServer
}

func NewClusteredServer() Server {
	return &clusteredServer{}
}

func (srv *clusteredServer) Stop() {}

func (srv *clusteredServer) OnConfigChange(_ context.Context, _ *config.Config) {
}
