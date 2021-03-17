package controlplane

import (
	"fmt"

	envoy_config_trace_v3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

func (srv *Server) buildTracingProvider(options *config.Options) (*envoy_config_trace_v3.Tracing_Http, error) {
	tracingOptions, err := config.NewTracingOptions(options)
	if err != nil {
		return nil, fmt.Errorf("invalid tracing config: %w", err)
	}

	switch tracingOptions.Provider {
	case trace.DatadogTracingProviderName:
		tracingTC, _ := anypb.New(&envoy_config_trace_v3.DatadogConfig{
			CollectorCluster: "datadog-apm",
			ServiceName:      tracingOptions.Service,
		})
		return &envoy_config_trace_v3.Tracing_Http{
			Name: "envoy.tracers.datadog",
			ConfigType: &envoy_config_trace_v3.Tracing_Http_TypedConfig{
				TypedConfig: tracingTC,
			},
		}, nil
	case trace.ZipkinTracingProviderName:
		if tracingOptions.ZipkinEndpoint.String() == "" {
			return nil, fmt.Errorf("missing zipkin url")
		}

		tracingTC, _ := anypb.New(
			&envoy_config_trace_v3.OpenCensusConfig{
				ZipkinExporterEnabled: true,
				ZipkinUrl:             tracingOptions.ZipkinEndpoint.String(),
				IncomingTraceContext: []envoy_config_trace_v3.OpenCensusConfig_TraceContext{
					envoy_config_trace_v3.OpenCensusConfig_B3,
					envoy_config_trace_v3.OpenCensusConfig_TRACE_CONTEXT,
					envoy_config_trace_v3.OpenCensusConfig_CLOUD_TRACE_CONTEXT,
					envoy_config_trace_v3.OpenCensusConfig_GRPC_TRACE_BIN,
				},
				OutgoingTraceContext: []envoy_config_trace_v3.OpenCensusConfig_TraceContext{
					envoy_config_trace_v3.OpenCensusConfig_B3,
					envoy_config_trace_v3.OpenCensusConfig_TRACE_CONTEXT,
					envoy_config_trace_v3.OpenCensusConfig_GRPC_TRACE_BIN,
				},
			},
		)
		return &envoy_config_trace_v3.Tracing_Http{
			Name: "envoy.tracers.opencensus",
			ConfigType: &envoy_config_trace_v3.Tracing_Http_TypedConfig{
				TypedConfig: tracingTC,
			},
		}, nil
	default:
		return nil, nil
	}
}
