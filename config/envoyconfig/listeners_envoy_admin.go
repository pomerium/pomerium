package envoyconfig

import (
	"context"
	"fmt"

	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildEnvoyAdminListener(_ context.Context, cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	filter := b.buildEnvoyAdminHTTPConnectionManagerFilter()

	filterChain := &envoy_config_listener_v3.FilterChain{
		Filters: []*envoy_config_listener_v3.Filter{
			filter,
		},
	}

	addr, err := parseAddress(cfg.Options.EnvoyAdminAddress)
	if err != nil {
		return nil, fmt.Errorf("envoy_admin_addr %s: %w", cfg.Options.EnvoyAdminAddress, err)
	}

	li := newTCPListener("envoy-admin", "envoy-admin", addr)
	li.FilterChains = []*envoy_config_listener_v3.FilterChain{filterChain}
	return li, nil
}

func (b *Builder) buildEnvoyAdminHTTPConnectionManagerFilter() *envoy_config_listener_v3.Filter {
	rc := newRouteConfiguration("envoy-admin", []*envoy_config_route_v3.VirtualHost{{
		Name:    "envoy-admin",
		Domains: []string{"*"},
		Routes: []*envoy_config_route_v3.Route{
			{
				Name: "envoy-admin",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"},
				},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: envoyAdminClusterName,
						},
					},
				},
			},
		},
	}})

	return b.HTTPConnectionManagerFilter(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "envoy-admin",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{
			HTTPRouterFilter(),
		},
	})
}

func shouldStartEnvoyAdminListener(options *config.Options) bool {
	return options.EnvoyAdminAddress != ""
}
