package controlplane

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const (
	clusterTypeURL  = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	listenerTypeURL = "type.googleapis.com/envoy.config.listener.v3.Listener"
)

func (srv *Server) buildDiscoveryResources(ctx context.Context) (map[string][]*envoy_service_discovery_v3.Resource, error) {
	ctx, span := srv.tracer.Start(ctx, "controlplane.Server.buildDiscoveryResources")
	defer span.End()

	cfg := srv.currentConfig.Load()

	log.Ctx(ctx).Debug().Msg("controlplane: building discovery resources")

	var clusterResources []*envoy_service_discovery_v3.Resource
	clusters, err := srv.Builder.BuildClusters(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error building clusters: %w", err)
	}
	for _, cluster := range clusters {
		clusterResources = append(clusterResources, &envoy_service_discovery_v3.Resource{
			Name:     cluster.Name,
			Version:  hex.EncodeToString(cryptutil.HashProto(cluster)),
			Resource: protoutil.NewAny(cluster),
		})
	}

	var listenerResources []*envoy_service_discovery_v3.Resource
	listeners, err := srv.Builder.BuildListeners(ctx, cfg, false)
	if err != nil {
		return nil, fmt.Errorf("error building listeners: %w", err)
	}
	for _, listener := range listeners {
		listenerResources = append(listenerResources, &envoy_service_discovery_v3.Resource{
			Name:     listener.Name,
			Version:  hex.EncodeToString(cryptutil.HashProto(listener)),
			Resource: protoutil.NewAny(listener),
		})
	}

	routeConfigurationResources := map[string][]*envoy_service_discovery_v3.Resource{}
	routeConfigurations, err := srv.Builder.BuildRouteConfigurations(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error building route configurations: %w", err)
	}
	for _, routeConfiguration := range routeConfigurations {
		typeURL := protoutil.GetTypeURL(routeConfiguration.Config)
		routeConfigurationResources[typeURL] = append(routeConfigurationResources[typeURL], &envoy_service_discovery_v3.Resource{
			Name:     routeConfiguration.Name,
			Version:  hex.EncodeToString(cryptutil.HashProto(routeConfiguration.Config)),
			Resource: protoutil.NewAny(routeConfiguration.Config),
		})
	}

	log.Ctx(ctx).Debug().
		Int("cluster-count", len(clusterResources)).
		Int("listener-count", len(listenerResources)).
		Int("route-configuration-count", len(routeConfigurationResources)).
		Msg("controlplane: built discovery resources")

	resources := map[string][]*envoy_service_discovery_v3.Resource{
		clusterTypeURL:  clusterResources,
		listenerTypeURL: listenerResources,
	}
	maps.Copy(resources, routeConfigurationResources)
	return resources, nil
}
