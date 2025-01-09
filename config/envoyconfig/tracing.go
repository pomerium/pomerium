package envoyconfig

import (
	"os"
	"strconv"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	envoy_extensions_filters_network_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_tracers_otel "github.com/envoyproxy/go-control-plane/envoy/extensions/tracers/opentelemetry/resource_detectors/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/extensions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func isTracingEnabled(cfg *config.Options) bool {
	if os.Getenv("OTEL_SDK_DISABLED") == "true" {
		return false
	}
	switch cfg.TracingProvider {
	case "none", "noop": // explicitly disabled from config
		return false
	case "": // unset
		return trace.IsEnabledViaEnvironment()
	default: // set to a non-empty value
		return !trace.IsDisabledViaEnvironment()
	}
}

func applyTracingConfig(
	mgr *envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager,
	opts *config.Options,
) {
	if !isTracingEnabled(opts) {
		return
	}

	mgr.EarlyHeaderMutationExtensions = []*envoy_config_core_v3.TypedExtensionConfig{
		{
			Name:        "envoy.http.early_header_mutation.trace_context",
			TypedConfig: marshalAny(&extensions.TraceContext{}),
		},
	}
	mgr.RequestIdExtension = &envoy_extensions_filters_network_http_connection_manager.RequestIDExtension{
		TypedConfig: marshalAny(&extensions.UuidxRequestIdConfig{
			PackTraceReason:              wrapperspb.Bool(true),
			UseRequestIdForTraceSampling: wrapperspb.Bool(true),
		}),
	}

	maxPathTagLength := uint32(1024)
	if value, ok := os.LookupEnv("OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT"); ok {
		if num, err := strconv.ParseUint(value, 10, 32); err == nil {
			maxPathTagLength = max(64, uint32(num))
		}
	}
	sampleRate := 1.0
	if value, ok := os.LookupEnv("OTEL_TRACES_SAMPLER_ARG"); ok {
		if rate, err := strconv.ParseFloat(value, 64); err == nil {
			sampleRate = rate
		}
	}
	if opts.TracingSampleRate != nil {
		sampleRate = *opts.TracingSampleRate
	}
	mgr.Tracing = &envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager_Tracing{
		RandomSampling:    &envoy_type_v3.Percent{Value: max(0.0, min(1.0, sampleRate)) * 100},
		Verbose:           true,
		SpawnUpstreamSpan: wrapperspb.Bool(true),
		Provider: &tracev3.Tracing_Http{
			Name: "envoy.tracers.pomerium_otel",
			ConfigType: &tracev3.Tracing_Http_TypedConfig{
				TypedConfig: marshalAny(&extensions.OpenTelemetryConfig{
					GrpcService: &envoy_config_core_v3.GrpcService{
						TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
								ClusterName: "pomerium-control-plane-grpc",
							},
						},
					},
					ServiceName: "Envoy",
					ResourceDetectors: []*envoy_config_core_v3.TypedExtensionConfig{
						{
							Name: "envoy.tracers.opentelemetry.resource_detectors.static_config",
							TypedConfig: marshalAny(&envoy_extensions_tracers_otel.StaticConfigResourceDetectorConfig{
								Attributes: map[string]string{
									"pomerium.envoy": "true",
								},
							}),
						},
					},
				}),
			},
		},
		// this allows full URLs to be displayed in traces, they are otherwise truncated
		MaxPathTagLength: wrapperspb.UInt32(maxPathTagLength),
	}
}
