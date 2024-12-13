package controlplane

import (
	"context"
	"encoding/hex"
	"fmt"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const (
	clusterTypeURL            = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	listenerTypeURL           = "type.googleapis.com/envoy.config.listener.v3.Listener"
	routeConfigurationTypeURL = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"
)

func (srv *Server) buildDiscoveryResources(ctx context.Context) (map[string][]*envoy_service_discovery_v3.Resource, error) {
	ctx, span := srv.tracer.Start(ctx, "controlplane.Server.buildDiscoveryResources")
	defer span.End()

	cfg := srv.currentConfig.Load()

	log.Ctx(ctx).Debug().Msg("controlplane: building discovery resources")

	eg, ctx := errgroup.WithContext(ctx)

	var clusterResources []*envoy_service_discovery_v3.Resource
	eg.Go(func() error {
		clusters, err := srv.Builder.BuildClusters(ctx, cfg)
		if err != nil {
			return fmt.Errorf("error building clusters: %w", err)
		}
		for _, cluster := range clusters {
			clusterResources = append(clusterResources, &envoy_service_discovery_v3.Resource{
				Name:     cluster.Name,
				Version:  hex.EncodeToString(cryptutil.HashProto(cluster)),
				Resource: protoutil.NewAny(cluster),
			})
		}
		return nil
	})

	var listenerResources []*envoy_service_discovery_v3.Resource
	eg.Go(func() error {
		listeners, err := srv.Builder.BuildListeners(ctx, cfg, false)
		if err != nil {
			return fmt.Errorf("error building listeners: %w", err)
		}
		for _, listener := range listeners {
			listenerResources = append(listenerResources, &envoy_service_discovery_v3.Resource{
				Name:     listener.Name,
				Version:  hex.EncodeToString(cryptutil.HashProto(listener)),
				Resource: protoutil.NewAny(listener),
			})
		}
		return nil
	})

	var routeConfigurationResources []*envoy_service_discovery_v3.Resource
	eg.Go(func() error {
		routeConfigurations, err := srv.Builder.BuildRouteConfigurations(ctx, cfg)
		if err != nil {
			return fmt.Errorf("error building route configurations: %w", err)
		}
		for _, routeConfiguration := range routeConfigurations {
			routeConfigurationResources = append(routeConfigurationResources, &envoy_service_discovery_v3.Resource{
				Name:     routeConfiguration.Name,
				Version:  hex.EncodeToString(cryptutil.HashProto(routeConfiguration)),
				Resource: protoutil.NewAny(routeConfiguration),
			})
		}
		return nil
	})

	err := eg.Wait()
	if err != nil {
		return nil, err
	}

	log.Ctx(ctx).Debug().
		Int("cluster-count", len(clusterResources)).
		Int("listener-count", len(listenerResources)).
		Int("route-configuration-count", len(routeConfigurationResources)).
		Msg("controlplane: built discovery resources")

	return map[string][]*envoy_service_discovery_v3.Resource{
		clusterTypeURL:            clusterResources,
		listenerTypeURL:           listenerResources,
		routeConfigurationTypeURL: routeConfigurationResources,
	}, nil
}
