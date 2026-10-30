// Package databroker contains a data broker implementation.
package databroker

import (
	"context"
	"maps"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

// A Server implements the databroker and registry interfaces.
type Server interface {
	configconnect.ConfigServiceHandler
	databrokerpb.CheckpointServiceServer
	databrokerpb.DataBrokerServiceServer
	registrypb.RegistryServer
	healthv2.ServiceEvaluator

	OnConfigChange(ctx context.Context, cfg *config.Config)
	Stop()
}

type serverWithoutStop struct {
	Server
}

func (srv serverWithoutStop) Stop() {}

func withoutStop(srv Server) Server {
	return serverWithoutStop{srv}
}

func withMember(info healthv2.Info, member string) healthv2.Info {
	details := maps.Clone(info.Details)
	if details == nil {
		details = map[string]string{}
	}
	details["member"] = member
	info.Details = details
	return info
}
