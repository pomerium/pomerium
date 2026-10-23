package xdsmgr

import (
	"context"
	"errors"
	"fmt"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/rs/zerolog"

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

func logEarlierACK(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest, latestNonce string) {
	log.Ctx(ctx).Debug().
		Str("type-url", req.GetTypeUrl()).
		Str("nonce", req.GetResponseNonce()).
		Str("latest-nonce", latestNonce).
		Msg("xdsmgr: ack of an earlier response")
}

func logSend(ctx context.Context, res *envoy_service_discovery_v3.DeltaDiscoveryResponse) {
	e := log.Ctx(ctx).Debug()
	if !e.Enabled() {
		return
	}
	resources, removed := res.GetResources(), res.GetRemovedResources()
	e = e.Str("type-url", res.GetTypeUrl()).
		Str("nonce", res.GetNonce()).
		Int("resource-count", len(resources)).
		Int("removed-resource-count", len(removed))
	// naming the resources costs allocations, so only trace level does it
	if log.GetLevel() <= zerolog.TraceLevel {
		e = e.Strs("resources", loggedNames(len(resources), func(i int) string {
			version := resources[i].GetVersion()
			return resources[i].GetName() + "@" + version[:min(len(version), 8)]
		})).
			Strs("removed-resources", loggedNames(len(removed), func(i int) string { return removed[i] }))
	}
	e.Msg("xdsmgr: sending resources")
}

// maxLoggedNames limits how many resource names a single log line lists.
const maxLoggedNames = 20

// loggedNames returns up to maxLoggedNames of count names, followed by how
// many were left out.
func loggedNames(count int, name func(i int) string) []string {
	names := make([]string, 0, min(count, maxLoggedNames)+1)
	for i := range min(count, maxLoggedNames) {
		names = append(names, name(i))
	}
	if count > maxLoggedNames {
		names = append(names, fmt.Sprintf("(%d more)", count-maxLoggedNames))
	}
	return names
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
