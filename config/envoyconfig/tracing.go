package envoyconfig

import (
	"fmt"
	"os"
	"strconv"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	envoy_extensions_filters_http_header_to_metadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	envoy_extensions_filters_network_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_tracers_otel "github.com/envoyproxy/go-control-plane/envoy/extensions/tracers/opentelemetry/resource_detectors/v3"
	metadatav3 "github.com/envoyproxy/go-control-plane/envoy/type/metadata/v3"
	envoy_tracing_v3 "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/extensions"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func applyTracingConfig(
	mgr *envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager,
	opts *config.Options,
) {
	mgr.HttpFilters = append([]*envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		tracingMetadataFilter(),
	}, mgr.HttpFilters...)

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
	requestTag := func(key string) *envoy_tracing_v3.CustomTag {
		return &envoy_tracing_v3.CustomTag{
			Tag: fmt.Sprintf("pomerium.%s", key),
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
									Key: key,
								},
							},
						},
					},
				},
			},
		}
	}
	mgr.Tracing = &envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager_Tracing{
		RandomSampling:    &envoy_type_v3.Percent{Value: opts.TracingSampleRate * 100},
		Verbose:           true,
		SpawnUpstreamSpan: wrapperspb.Bool(true),
		Provider: &tracev3.Tracing_Http{
			Name: "envoy.tracers.opentelemetry",
			ConfigType: &tracev3.Tracing_Http_TypedConfig{
				TypedConfig: marshalAny(&tracev3.OpenTelemetryConfig{
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
		CustomTags: []*envoy_tracing_v3.CustomTag{
			requestTag("traceparent"),
			requestTag("tracestate"),
			requestTag("external-parent-span"),
		},
	}
}

func tracingMetadataFilter() *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	traceparentRule := &envoy_extensions_filters_http_header_to_metadata.Config_Rule{
		Header: "x-pomerium-traceparent",
		OnHeaderPresent: &envoy_extensions_filters_http_header_to_metadata.Config_KeyValuePair{
			MetadataNamespace: "pomerium.internal",
			Key:               "traceparent",
		},
		Remove: false,
	}
	tracestateRule := &envoy_extensions_filters_http_header_to_metadata.Config_Rule{
		Header: "x-pomerium-tracestate",
		OnHeaderPresent: &envoy_extensions_filters_http_header_to_metadata.Config_KeyValuePair{
			MetadataNamespace: "pomerium.internal",
			Key:               "tracestate",
		},
		Remove: false,
	}
	externalParentSpanRule := &envoy_extensions_filters_http_header_to_metadata.Config_Rule{
		Header: "x-pomerium-external-parent-span",
		OnHeaderPresent: &envoy_extensions_filters_http_header_to_metadata.Config_KeyValuePair{
			MetadataNamespace: "pomerium.internal",
			Key:               "external-parent-span",
		},
		Remove: true,
	}
	samplingDecisionRule := &envoy_extensions_filters_http_header_to_metadata.Config_Rule{
		Header: "x-pomerium-sampling-decision",
		OnHeaderPresent: &envoy_extensions_filters_http_header_to_metadata.Config_KeyValuePair{
			MetadataNamespace: "pomerium.internal",
			Key:               "sampling-decision",
		},
		Remove: true,
	}
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.header_to_metadata",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: marshalAny(&envoy_extensions_filters_http_header_to_metadata.Config{
				RequestRules: []*envoy_extensions_filters_http_header_to_metadata.Config_Rule{
					traceparentRule,
					tracestateRule,
					externalParentSpanRule,
					samplingDecisionRule,
				},
				ResponseRules: []*envoy_extensions_filters_http_header_to_metadata.Config_Rule{
					traceparentRule,
					tracestateRule,
				},
			}),
		},
	}
}
