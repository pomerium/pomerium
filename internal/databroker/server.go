// Package databroker contains a data broker implementation.
package databroker

import (
	"context"

	"github.com/pomerium/pomerium/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

// A Server implements the databroker and registry interfaces.
type Server interface {
	databrokerpb.CheckpointServiceServer
	databrokerpb.DataBrokerServiceServer
	registrypb.RegistryServer

	OnConfigChange(ctx context.Context, cfg *config.Config)
	Stop()
}
