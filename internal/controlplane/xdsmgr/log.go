package xdsmgr

import (
	"context"
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

// logNACK logs a response envoy rejected. Envoy keeps serving the resources
// it last accepted, and the rejected ones are not sent again until they
// change.
func logNACK(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
	log.Ctx(ctx).Error().
		Str("type-url", req.GetTypeUrl()).
		Str("nonce", req.GetResponseNonce()).
		Any("error-detail", req.GetErrorDetail()).
		Msg("xdsmgr: nack")
}

func logACK(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
	log.Ctx(ctx).Debug().
		Str("type-url", req.GetTypeUrl()).
		Str("nonce", req.GetResponseNonce()).
		Msg("xdsmgr: ack")
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
	// naming the resources costs allocations, so only trace level does it.
	// The global level decides, because testenv pins its context loggers at
	// debug while the e2e tests raise the global level to trace.
	if log.GetLevel() <= zerolog.TraceLevel {
		e = e.Strs("resources", loggedNames(resources, func(r *envoy_service_discovery_v3.Resource) string {
			version := r.GetVersion()
			return r.GetName() + "@" + version[:min(len(version), 8)]
		})).
			Strs("removed-resources", loggedNames(removed, func(name string) string { return name }))
	}
	e.Msg("xdsmgr: sending resources")
}

// maxLoggedNames limits how many resource names a single log line lists.
const maxLoggedNames = 20

// loggedNames names up to maxLoggedNames of the items, followed by how many
// were left out.
func loggedNames[T any](items []T, name func(T) string) []string {
	shown := items[:min(len(items), maxLoggedNames)]
	names := make([]string, 0, len(shown)+1)
	for _, item := range shown {
		names = append(names, name(item))
	}
	if len(items) > len(shown) {
		names = append(names, fmt.Sprintf("(%d more)", len(items)-len(shown)))
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
