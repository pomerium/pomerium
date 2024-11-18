package envoyconfig

import (
	"context"
	"crypto/tls"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
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
