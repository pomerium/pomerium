package envoyconfig

import (
	"context"
	"fmt"
	"strconv"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildOutboundListener(
	ctx context.Context,
	cfg *config.Config,
) (*envoy_config_listener_v3.Listener, error) {
	outboundPort, err := strconv.Atoi(cfg.OutboundPort)
	if err != nil {
		return nil, fmt.Errorf("invalid outbound port: %w", err)
	}

	filter, err := b.buildOutboundHTTPConnectionManager(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error building outbound http connection manager filter: %w", err)
	}

	li := &envoy_config_listener_v3.Listener{
		Name: "outbound-ingress",
		Address: &envoy_config_core_v3.Address{
			Address: &envoy_config_core_v3.Address_SocketAddress{
				SocketAddress: &envoy_config_core_v3.SocketAddress{
					Address: "127.0.0.1",
					PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
						PortValue: uint32(outboundPort),
					},
				},
			},
		},
		FilterChains: []*envoy_config_listener_v3.FilterChain{{
			Name:    "outbound-ingress",
			Filters: []*envoy_config_listener_v3.Filter{filter},
		}},
	}

	return li, nil
}

func (b *Builder) buildOutboundHTTPConnectionManager(
	ctx context.Context,
	cfg *config.Config,
) (*envoy_config_listener_v3.Filter, error) {
	tc := marshalAny(&envoy_http_connection_manager.HttpConnectionManager{})

	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: tc,
		},
	}, nil
}
