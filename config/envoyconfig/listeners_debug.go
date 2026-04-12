package envoyconfig

import (
	"fmt"

	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildDebugListener(cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	filter := b.buildDebugHTTPConnectionManagerFilter()

	filterChain := &envoy_config_listener_v3.FilterChain{
		Filters: []*envoy_config_listener_v3.Filter{
			filter,
		},
	}

	addr, err := parseAddress(cfg.Options.DebugAddress.String)
	if err != nil {
		return nil, fmt.Errorf("error parsing debug address %s: %w", cfg.Options.DebugAddress.String, err)
	}

	li := newTCPListener("debug", "debug", addr)
	li.FilterChains = []*envoy_config_listener_v3.FilterChain{filterChain}
	return li, nil
}

func (b *Builder) buildDebugHTTPConnectionManagerFilter() *envoy_config_listener_v3.Filter {
	rc := newRouteConfiguration("debug", []*envoy_config_route_v3.VirtualHost{{
		Name:    "debug",
		Domains: []string{"*"},
		Routes: []*envoy_config_route_v3.Route{
			{
				Name: "debug",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"},
				},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: "pomerium-control-plane-debug",
						},
					},
				},
			},
		},
	}})

	return b.HTTPConnectionManagerFilter(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "debug",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{
			HTTPRouterFilter(),
		},
	})
}

func shouldStartDebugListener(options *config.Options) bool {
	return options.DebugAddress.IsValid()
}
