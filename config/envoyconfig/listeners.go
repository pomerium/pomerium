package envoyconfig

import (
	"context"
	"runtime"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

const listenerBufferLimit uint32 = 32 * 1024

// BuildListeners builds envoy listeners from the given config.
func (b *Builder) BuildListeners(
	ctx context.Context,
	cfg *config.Config,
	fullyStatic bool,
) ([]*envoy_config_listener_v3.Listener, error) {
	ctx, span := trace.Continue(ctx, "envoyconfig.Builder.BuildListeners")
	defer span.End()

	var listeners []*envoy_config_listener_v3.Listener

	if shouldStartMainListener(cfg.Options) {
		li, err := b.buildMainListener(ctx, cfg, fullyStatic, false)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
		li = proto.Clone(li).(*envoy_config_listener_v3.Listener)
		li.Name = "http-ingress-internal-listener"
		li.Address = nil
		li.EnableReusePort = nil // not supported for an internal listener
		li.ListenerSpecifier = &envoy_config_listener_v3.Listener_InternalListener{
			InternalListener: &envoy_config_listener_v3.Listener_InternalListenerConfig{},
		}
		listeners = append(listeners, li)
		// for HTTP/3 we add another main listener that listens on UDP
		if cfg.Options.GetCodecType() == config.CodecTypeHTTP3 {
			li, err := b.buildMainListener(ctx, cfg, fullyStatic, true)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, li)
		}
	}

	if shouldStartGRPCListener(cfg.Options) {
		li, err := b.buildGRPCListener(ctx, cfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	if shouldStartMetricsListener(cfg.Options) {
		li, err := b.buildMetricsListener(cfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	if shouldStartEnvoyAdminListener(cfg.Options) {
		li, err := b.buildEnvoyAdminListener(ctx, cfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	li, err := b.buildOutboundListener(cfg)
	if err != nil {
		return nil, err
	}
	listeners = append(listeners, li)

	return listeners, nil
}

// newListener creates envoy listener with certain default values
func newListener(name string) *envoy_config_listener_v3.Listener {
	return &envoy_config_listener_v3.Listener{
		Name:                          name,
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(listenerBufferLimit),

		// SO_REUSEPORT only works properly on linux and is force-disabled by
		// envoy on mac and windows, so we disable it explitly to avoid a
		// noisy log message
		EnableReusePort: wrapperspb.Bool(runtime.GOOS == "linux"),
	}
}

// newQUICListener creates a new envoy listener that handles QUIC connections.
func newQUICListener(name string, address *envoy_config_core_v3.Address) *envoy_config_listener_v3.Listener {
	li := newListener(name)
	li.Address = address
	li.UdpListenerConfig = &envoy_config_listener_v3.UdpListenerConfig{
		QuicOptions: &envoy_config_listener_v3.QuicProtocolOptions{},
		DownstreamSocketConfig: &envoy_config_core_v3.UdpSocketConfig{
			PreferGro: &wrapperspb.BoolValue{Value: true},
		},
	}
	return li
}

// newTCPListener creates a new envoy listener that handles TCP connections.
func newTCPListener(name string, address *envoy_config_core_v3.Address) *envoy_config_listener_v3.Listener {
	li := newListener(name)
	li.Address = address
	return li
}
