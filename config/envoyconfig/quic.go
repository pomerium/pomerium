package envoyconfig

import (
	"context"
	"crypto/tls"
	"fmt"

	envoy_config_common_mutation_rules_v3 "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_filters_http_header_mutation_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	envoy_extensions_filters_network_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_quic_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/quic/v3"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildDownstreamQUICTransportSocket(
	ctx context.Context,
	cfg *config.Config,
	certs []tls.Certificate,
) (*envoy_config_core_v3.TransportSocket, error) {
	tlsContext, err := b.buildDownstreamTLSContextMulti(ctx, cfg, certs)
	if err != nil {
		return nil, err
	}
	tlsContext.CommonTlsContext.AlpnProtocols = nil

	return &envoy_config_core_v3.TransportSocket{
		Name: "envoy.transport_sockets.quic",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: marshalAny(&envoy_extensions_transport_sockets_quic_v3.QuicDownstreamTransport{
				DownstreamTlsContext: tlsContext,
			}),
		},
	}, nil
}

func newQUICAltSvcHeaderFilter(cfg *config.Config) *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	var advertisePort uint32
	if cfg.Options.HTTP3AdvertisePort.Valid {
		advertisePort = cfg.Options.HTTP3AdvertisePort.Uint32
	} else {
		listenAddr := buildUDPAddress(cfg.Options.Addr, 443)
		advertisePort = listenAddr.GetSocketAddress().GetPortValue()
	}
	return HTTPHeaderMutationsFilter(&envoy_extensions_filters_http_header_mutation_v3.HeaderMutation{
		Mutations: &envoy_extensions_filters_http_header_mutation_v3.Mutations{
			ResponseMutations: []*envoy_config_common_mutation_rules_v3.HeaderMutation{{
				Action: &envoy_config_common_mutation_rules_v3.HeaderMutation_Append{
					Append: &envoy_config_core_v3.HeaderValueOption{
						Header: &envoy_config_core_v3.HeaderValue{
							Key:   "alt-svc",
							Value: fmt.Sprintf(`h3=":%d"; ma=86400`, advertisePort),
						},
					},
				},
			}},
		},
	})
}
