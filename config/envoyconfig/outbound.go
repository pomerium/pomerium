package envoyconfig

import (
	"fmt"
	"strconv"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildOutboundListener(cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	outboundPort, err := strconv.ParseUint(cfg.OutboundPort, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid outbound port %v: %w", cfg.OutboundPort, err)
	}

	filter := b.buildOutboundHTTPConnectionManager()

	li := newListener("outbound-ingress")
	li.Address = &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_SocketAddress{
			SocketAddress: &envoy_config_core_v3.SocketAddress{
				Address: "127.0.0.1",
				PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
					PortValue: uint32(outboundPort),
				},
			},
		},
	}
	li.FilterChains = []*envoy_config_listener_v3.FilterChain{{
		Name:    "outbound-ingress",
		Filters: []*envoy_config_listener_v3.Filter{filter},
	}}
	return li, nil
}

func (b *Builder) buildOutboundHTTPConnectionManager() *envoy_config_listener_v3.Filter {
	rc := b.buildOutboundRouteConfiguration()

	tc := marshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "grpc_egress",
		// limit request first byte to last byte time
		RequestTimeout: &durationpb.Duration{
			Seconds: 15,
		},
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{
			HTTPRouterFilter(),
		},
	})

	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: tc,
		},
	}
}

func (b *Builder) buildOutboundRouteConfiguration() *envoy_config_route_v3.RouteConfiguration {
	return newRouteConfiguration("grpc", []*envoy_config_route_v3.VirtualHost{{
		Name:    "grpc",
		Domains: []string{"*"},
		Routes:  b.buildOutboundRoutes(),
	}})
}

func (b *Builder) buildOutboundRoutes() []*envoy_config_route_v3.Route {
	type Def struct {
		Cluster  string
		Prefixes []string
	}
	defs := []Def{
		{
			Cluster: "pomerium-authorize",
			Prefixes: []string{
				"/envoy.service.auth.v3.Authorization/",
			},
		},
		{
			Cluster: "pomerium-databroker",
			Prefixes: []string{
				"/databroker.DataBrokerService/",
				"/registry.Registry/",
			},
		},
		{
			Cluster: "pomerium-control-plane-grpc",
			Prefixes: []string{
				"/",
			},
		},
	}
	var routes []*envoy_config_route_v3.Route
	for _, def := range defs {
		for _, prefix := range def.Prefixes {
			routes = append(routes, &envoy_config_route_v3.Route{
				Name: def.Cluster,
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: prefix},
					Grpc:          &envoy_config_route_v3.RouteMatch_GrpcRouteMatchOptions{},
				},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: def.Cluster,
						},
						// rewrite the host header
						HostRewriteSpecifier: &envoy_config_route_v3.RouteAction_AutoHostRewrite{
							AutoHostRewrite: wrapperspb.Bool(true),
						},
						// disable the timeout to support grpc streaming
						Timeout:     durationpb.New(0),
						IdleTimeout: durationpb.New(0),
					},
				},
			})
		}
	}
	routes = append(routes, &envoy_config_route_v3.Route{
		Name: "envoy-metrics",
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/envoy/stats/prometheus"},
		},
		Action: &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{
				ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
					Cluster: envoyAdminClusterName,
				},
				PrefixRewrite: "/stats/prometheus",
			},
		},
	})
	return routes
}
