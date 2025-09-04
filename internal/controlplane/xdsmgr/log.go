package xdsmgr

import (
	"context"
	"errors"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var (
	clusterTypeURL            = protoutil.GetTypeURL((*envoy_config_cluster_v3.Cluster)(nil))
	listenerTypeURL           = protoutil.GetTypeURL((*envoy_config_listener_v3.Listener)(nil))
	routeConfigurationTypeURL = protoutil.GetTypeURL((*envoy_config_route_v3.RouteConfiguration)(nil))
)

func logNACK(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
	log.Ctx(ctx).Debug().
		Str("type-url", req.GetTypeUrl()).
		Any("error-detail", req.GetErrorDetail()).
		Msg("xdsmgr: nack")

	health.ReportError(getHealthCheck(req.GetTypeUrl()), errors.New(req.GetErrorDetail().GetMessage()))
}

func logACK(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
	log.Ctx(ctx).Debug().
		Str("type-url", req.GetTypeUrl()).
		Msg("xdsmgr: ack")

	health.ReportRunning(getHealthCheck(req.GetTypeUrl()))
}

func getHealthCheck(typeURL string) health.Check {
	switch typeURL {
	case clusterTypeURL:
		return health.XDSCluster
	case listenerTypeURL:
		return health.XDSListener
	case routeConfigurationTypeURL:
		return health.XDSRouteConfiguration
	default:
		return health.XDSOther
	}
}
