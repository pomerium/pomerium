package envoyconfig

import (
	"context"
	"fmt"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildGRPCListener(ctx context.Context, cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	filter := b.buildGRPCHTTPConnectionManagerFilter()

	filterChain := envoy_config_listener_v3.FilterChain{
		Filters: []*envoy_config_listener_v3.Filter{filter},
	}

	var address *envoy_config_core_v3.Address
	if cfg.Options.GetGRPCInsecure() {
		address = buildTCPAddress(cfg.Options.GetGRPCAddr(), 80)
	} else {
		address = buildTCPAddress(cfg.Options.GetGRPCAddr(), 443)
	}

	li := newTCPListener("grpc-ingress", address)
	li.FilterChains = []*envoy_config_listener_v3.FilterChain{&filterChain}

	if cfg.Options.GetGRPCInsecure() {
		return li, nil
	}

	li.ListenerFilters = []*envoy_config_listener_v3.ListenerFilter{
		TLSInspectorFilter(),
	}

	allCertificates, err := getAllCertificates(cfg)
	if err != nil {
		return nil, err
	}
	envoyCerts, err := b.envoyTLSCertificatesFromGoTLSCertificates(ctx, allCertificates)
	if err != nil {
		return nil, err
	}
	tlsContext := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams:       tlsDownstreamParams,
			TlsCertificates: envoyCerts,
			AlpnProtocols:   []string{"h2"}, // gRPC requires HTTP/2
		},
	}
	filterChain.TransportSocket = newDownstreamTLSTransportSocket(tlsContext)
	return li, nil
}

func (b *Builder) buildGRPCHTTPConnectionManagerFilter() *envoy_config_listener_v3.Filter {
	allow := []string{
		"envoy.service.auth.v3.Authorization",
		"databroker.DataBrokerService",
		"registry.Registry",
		"grpc.health.v1.Health",
	}
	routes := make([]*envoy_config_route_v3.Route, 0, len(allow))
	for _, svc := range allow {
		routes = append(routes, &envoy_config_route_v3.Route{
			Name: "grpc",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: fmt.Sprintf("/%s/", svc)},
				Grpc:          &envoy_config_route_v3.RouteMatch_GrpcRouteMatchOptions{},
			},
			Action: &envoy_config_route_v3.Route_Route{
				Route: &envoy_config_route_v3.RouteAction{
					ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
						Cluster: "pomerium-control-plane-grpc",
					},
					// disable the timeout to support grpc streaming
					Timeout: &durationpb.Duration{
						Seconds: 0,
					},
					IdleTimeout: &durationpb.Duration{
						Seconds: 0,
					},
				},
			},
		})
	}
	rc := newRouteConfiguration("grpc", []*envoy_config_route_v3.VirtualHost{{
		Name:    "grpc",
		Domains: []string{"*"},
		Routes:  routes,
	}})

	return HTTPConnectionManagerFilter(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "grpc_ingress",
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
}

func shouldStartGRPCListener(options *config.Options) bool {
	if options.GetGRPCAddr() == "" {
		return false
	}

	return config.IsAuthorize(options.Services) || config.IsDataBroker(options.Services)
}
