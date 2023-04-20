package controlplane

import (
	"context"
	"encoding/hex"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const (
	clusterTypeURL            = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	listenerTypeURL           = "type.googleapis.com/envoy.config.listener.v3.Listener"
	routeConfigurationTypeURL = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"
)

func (srv *Server) buildDiscoveryResources(ctx context.Context) (map[string][]*envoy_service_discovery_v3.Resource, error) {
	resources := map[string][]*envoy_service_discovery_v3.Resource{}
	cfg := srv.currentConfig.Load()

	clusters, err := srv.Builder.BuildClusters(ctx, cfg.Config)
	if err != nil {
		return nil, err
	}
	for _, cluster := range clusters {
		resources[clusterTypeURL] = append(resources[clusterTypeURL], &envoy_service_discovery_v3.Resource{
			Name:     cluster.Name,
			Version:  hex.EncodeToString(cryptutil.HashProto(cluster)),
			Resource: protoutil.NewAny(cluster),
		})
	}

	listeners, err := srv.Builder.BuildListeners(ctx, cfg.Config, false)
	if err != nil {
		return nil, err
	}
	for _, listener := range listeners {
		resources[listenerTypeURL] = append(resources[listenerTypeURL], &envoy_service_discovery_v3.Resource{
			Name:     listener.Name,
			Version:  hex.EncodeToString(cryptutil.HashProto(listener)),
			Resource: protoutil.NewAny(listener),
		})
	}

	routeConfigurations, err := srv.Builder.BuildRouteConfigurations(ctx, cfg.Config)
	if err != nil {
		return nil, err
	}
	for _, routeConfiguration := range routeConfigurations {
		resources[routeConfigurationTypeURL] = append(resources[routeConfigurationTypeURL], &envoy_service_discovery_v3.Resource{
			Name:     routeConfiguration.Name,
			Version:  hex.EncodeToString(cryptutil.HashProto(routeConfiguration)),
			Resource: protoutil.NewAny(routeConfiguration),
		})
	}

	return resources, nil
}
