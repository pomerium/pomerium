package envoyconfig

import (
	"context"
	"strings"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	envoy_extensions_filters_http_header_to_metadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	envoy_extensions_filters_network_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_tracers_otel "github.com/envoyproxy/go-control-plane/envoy/extensions/tracers/opentelemetry/resource_detectors/v3"
	metadatav3 "github.com/envoyproxy/go-control-plane/envoy/type/metadata/v3"
	envoy_tracing_v3 "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	extensions_trace_context "github.com/pomerium/envoy-custom/api/extensions/http/early_header_mutation/trace_context"
	extensions_uuidx "github.com/pomerium/envoy-custom/api/extensions/request_id/uuidx"
	extensions_pomerium_otel "github.com/pomerium/envoy-custom/api/extensions/tracers/pomerium_otel"
	"github.com/pomerium/pomerium/config/otelconfig"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func isTracingEnabled(cfg *otelconfig.Config) bool {
	if trace.IsOtelSDKDisabled() {
		return false
	}
	if cfg.OtelTracesExporter == nil {
		return false
	}
	switch *cfg.OtelTracesExporter {
	case "none", "noop", "":
		return false
	default:
		return cfg.OtelExporterOtlpTracesEndpoint != nil || cfg.OtelExporterOtlpEndpoint != nil
	}
}

func applyTracingConfig(
	ctx context.Context,
	mgr *envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager,
	opts *otelconfig.Config,
) {
	if !isTracingEnabled(opts) {
		return
	}
	mgr.EarlyHeaderMutationExtensions = []*envoy_config_core_v3.TypedExtensionConfig{
		{
			Name:        "envoy.http.early_header_mutation.trace_context",
			TypedConfig: marshalAny(&extensions_trace_context.TraceContext{}),
		},
	}
	mgr.RequestIdExtension = &envoy_extensions_filters_network_http_connection_manager.RequestIDExtension{
		TypedConfig: marshalAny(&extensions_uuidx.UuidxRequestIdConfig{
			PackTraceReason:              wrapperspb.Bool(true),
			UseRequestIdForTraceSampling: wrapperspb.Bool(true),
		}),
	}

	var grpcHeaders []*envoy_config_core_v3.HeaderValue
	for _, kv := range opts.OtelExporterOtlpTracesHeaders {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			grpcHeaders = append(grpcHeaders, &envoy_config_core_v3.HeaderValue{
				Key:   k,
				Value: v,
			})
		}
	}
	var timeout *durationpb.Duration
	if opts.OtelExporterOtlpTracesTimeout != nil {
		timeout = durationpb.New(time.Duration(*opts.OtelExporterOtlpTracesTimeout) * time.Millisecond)
	}

	mgr.Tracing = &envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager_Tracing{
		Verbose:           true,
		SpawnUpstreamSpan: wrapperspb.Bool(true),
		Provider: &tracev3.Tracing_Http{
			Name: "envoy.tracers.pomerium_otel",
			ConfigType: &tracev3.Tracing_Http_TypedConfig{
				TypedConfig: marshalAny(&extensions_pomerium_otel.OpenTelemetryConfig{
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
					GrpcService: &envoy_config_core_v3.GrpcService{
						TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
								ClusterName: "pomerium-control-plane-grpc",
							},
						},
						InitialMetadata: grpcHeaders,
						Timeout:         timeout,
					},
				}),
			},
		},
	}
	if opts.OtelAttributeValueLengthLimit != nil {
		mgr.Tracing.MaxPathTagLength = wrapperspb.UInt32(max(64, min(32768, uint32(*opts.OtelAttributeValueLengthLimit))))
	}
	if opts.OtelTracesSamplerArg != nil {
		mgr.Tracing.RandomSampling = &envoy_type_v3.Percent{Value: max(0.0, min(1.0, *opts.OtelTracesSamplerArg)) * 100}
	}

	debugFlags := trace.DebugFlagsFromContext(ctx)
	if debugFlags.Check(trace.TrackSpanReferences) {
		mgr.HttpFilters = append([]*envoy_extensions_filters_network_http_connection_manager.HttpFilter{
			{
				Name: "envoy.filters.http.header_to_metadata",
				ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
					TypedConfig: marshalAny(&envoy_extensions_filters_http_header_to_metadata.Config{
						RequestRules: []*envoy_extensions_filters_http_header_to_metadata.Config_Rule{
							{
								Header: "x-pomerium-external-parent-span",
								OnHeaderPresent: &envoy_extensions_filters_http_header_to_metadata.Config_KeyValuePair{
									MetadataNamespace: "pomerium.internal",
									Key:               "external-parent-span",
								},
								Remove: true,
							},
						},
					}),
				},
			},
		}, mgr.HttpFilters...)
		mgr.Tracing.CustomTags = append(mgr.Tracing.CustomTags, &envoy_tracing_v3.CustomTag{
			Tag: "pomerium.external-parent-span",
			Type: &envoy_tracing_v3.CustomTag_Metadata_{
				Metadata: &envoy_tracing_v3.CustomTag_Metadata{
					Kind: &metadatav3.MetadataKind{
						Kind: &metadatav3.MetadataKind_Request_{
							Request: &metadatav3.MetadataKind_Request{},
						},
					},
					MetadataKey: &metadatav3.MetadataKey{
						Key: "pomerium.internal",
						Path: []*metadatav3.MetadataKey_PathSegment{
							{
								Segment: &metadatav3.MetadataKey_PathSegment_Key{
									Key: "external-parent-span",
								},
							},
						},
					},
				},
			},
		})
	}
}
