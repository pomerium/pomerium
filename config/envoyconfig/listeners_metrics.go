package envoyconfig

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"

	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

func (b *Builder) buildMetricsListener(cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	filter := b.buildMetricsHTTPConnectionManagerFilter()

	filterChain := &envoy_config_listener_v3.FilterChain{
		Filters: []*envoy_config_listener_v3.Filter{
			filter,
		},
	}

	cert, err := cfg.Options.GetMetricsCertificate()
	if err != nil {
		return nil, err
	}
	if cert != nil {
		dtc := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
			CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
				TlsParams: tlsDownstreamParams,
				TlsCertificates: []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{
					b.envoyTLSCertificateFromGoTLSCertificate(context.TODO(), cert),
				},
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
		}

		if cfg.Options.MetricsClientCA != "" {
			bs, err := base64.StdEncoding.DecodeString(cfg.Options.MetricsClientCA)
			if err != nil {
				return nil, fmt.Errorf("xds: invalid metrics_client_ca: %w", err)
			}

			dtc.RequireClientCertificate = wrapperspb.Bool(true)
			dtc.CommonTlsContext.ValidationContextType = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
					TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_VERIFY_TRUST_CHAIN,
					TrustedCa:              b.filemgr.BytesDataSource("metrics_client_ca.pem", bs),
				},
			}
		} else if cfg.Options.MetricsClientCAFile != "" {
			dtc.RequireClientCertificate = wrapperspb.Bool(true)
			dtc.CommonTlsContext.ValidationContextType = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
					TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_VERIFY_TRUST_CHAIN,
					TrustedCa:              b.filemgr.FileDataSource(cfg.Options.MetricsClientCAFile),
				},
			}
		}

		filterChain.TransportSocket = newDownstreamTLSTransportSocket(dtc)
	}

	// we ignore the host part of the address, only binding to
	host, port, err := net.SplitHostPort(cfg.Options.MetricsAddr)
	if err != nil {
		return nil, fmt.Errorf("metrics_addr %s: %w", cfg.Options.MetricsAddr, err)
	}
	if port == "" {
		return nil, fmt.Errorf("metrics_addr %s: port is required", cfg.Options.MetricsAddr)
	}
	// unless an explicit IP address was provided, and bind to all interfaces if hostname was provided
	if net.ParseIP(host) == nil {
		host = ""
	}

	addr := buildAddress(net.JoinHostPort(host, port), 9902)
	li := newListener(fmt.Sprintf("metrics-ingress-%d", hashutil.MustHash(addr)))
	li.Address = addr
	li.FilterChains = []*envoy_config_listener_v3.FilterChain{filterChain}
	return li, nil
}

func (b *Builder) buildMetricsHTTPConnectionManagerFilter() *envoy_config_listener_v3.Filter {
	rc := newRouteConfiguration("metrics", []*envoy_config_route_v3.VirtualHost{{
		Name:    "metrics",
		Domains: []string{"*"},
		Routes: []*envoy_config_route_v3.Route{
			{
				Name: "envoy-metrics",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: metrics.EnvoyMetricsPath},
				},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: envoyAdminClusterName,
						},
						PrefixRewrite: "/stats/prometheus",
					},
				},
			},
			{
				Name: "metrics",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"},
				},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: "pomerium-control-plane-metrics",
						},
					},
				},
			},
		},
	}})

	return HTTPConnectionManagerFilter(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "metrics",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{
			HTTPRouterFilter(),
		},
	})
}

func shouldStartMetricsListener(options *config.Options) bool {
	return options.MetricsAddr != ""
}
