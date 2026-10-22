package xdsmgr

import (
	"context"
	"errors"
	"fmt"

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
		Str("nonce", req.GetResponseNonce()).
		Any("error-detail", req.GetErrorDetail()).
		Msg("xdsmgr: nack")

	health.ReportError(getHealthCheck(req.GetTypeUrl()), errors.New(req.GetErrorDetail().GetMessage()))
}

func logACK(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
	log.Ctx(ctx).Debug().
		Str("type-url", req.GetTypeUrl()).
		Str("nonce", req.GetResponseNonce()).
		Msg("xdsmgr: ack")

	health.ReportRunning(getHealthCheck(req.GetTypeUrl()))
}

// maxLoggedNames limits how many resource names a single log line lists.
const maxLoggedNames = 20

// resourceRefs returns "name@version" for each resource, with the version
// shortened, so a log line shows which resources changed.
func resourceRefs(resources []*envoy_service_discovery_v3.Resource) []string {
	refs := make([]string, 0, len(resources))
	for _, resource := range resources {
		refs = append(refs, resource.GetName()+"@"+resource.GetVersion()[:min(len(resource.GetVersion()), 8)])
	}
	return limitNames(refs)
}

func limitNames(names []string) []string {
	if len(names) <= maxLoggedNames {
		return names
	}
	return append(names[:maxLoggedNames:maxLoggedNames], fmt.Sprintf("(%d more)", len(names)-maxLoggedNames))
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
