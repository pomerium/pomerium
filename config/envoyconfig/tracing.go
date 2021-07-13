package envoyconfig

import (
	"fmt"
	"net"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_trace_v3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

func buildTracingCluster(options *config.Options) (*envoy_config_cluster_v3.Cluster, error) {
	tracingOptions, err := config.NewTracingOptions(options)
	if err != nil {
		return nil, fmt.Errorf("envoyconfig: invalid tracing config: %w", err)
	}

	switch tracingOptions.Provider {
	case trace.DatadogTracingProviderName:
		addr, _ := parseAddress("127.0.0.1:8126")

		if options.TracingDatadogAddress != "" {
			addr, err = parseAddress(options.TracingDatadogAddress)
			if err != nil {
				return nil, fmt.Errorf("envoyconfig: invalid tracing datadog address: %w", err)
			}
		}

		endpoints := []*envoy_config_endpoint_v3.LbEndpoint{{
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
				Endpoint: &envoy_config_endpoint_v3.Endpoint{
					Address: addr,
				},
			},
		}}

		return &envoy_config_cluster_v3.Cluster{
			Name: "datadog-apm",
			ConnectTimeout: &durationpb.Duration{
				Seconds: 5,
			},
			ClusterDiscoveryType: getClusterDiscoveryType(endpoints),
			LbPolicy:             envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
			LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "datadog-apm",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
					LbEndpoints: endpoints,
				}},
			},
		}, nil
	case trace.ZipkinTracingProviderName:
		host := tracingOptions.ZipkinEndpoint.Host
		if _, port, _ := net.SplitHostPort(host); port == "" {
			if tracingOptions.ZipkinEndpoint.Scheme == "https" {
				host = net.JoinHostPort(host, "443")
			} else {
				host = net.JoinHostPort(host, "80")
			}
		}

		addr, err := parseAddress(host)
		if err != nil {
			return nil, fmt.Errorf("envoyconfig: invalid tracing zipkin address: %w", err)
		}

		endpoints := []*envoy_config_endpoint_v3.LbEndpoint{{
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
				Endpoint: &envoy_config_endpoint_v3.Endpoint{
					Address: addr,
				},
			},
		}}
		return &envoy_config_cluster_v3.Cluster{
			Name: "zipkin",
			ConnectTimeout: &durationpb.Duration{
				Seconds: 5,
			},
			ClusterDiscoveryType: getClusterDiscoveryType(endpoints),
			LbPolicy:             envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
			LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "zipkin",
				Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
					LbEndpoints: endpoints,
				}},
			},
		}, nil
	default:
		return nil, nil
	}
}

func buildTracingHTTP(options *config.Options) (*envoy_config_trace_v3.Tracing_Http, error) {
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
		path := tracingOptions.ZipkinEndpoint.Path
		if path == "" {
			path = "/"
		}
		tracingTC, _ := anypb.New(&envoy_config_trace_v3.ZipkinConfig{
			CollectorCluster:         "zipkin",
			CollectorEndpoint:        path,
			CollectorEndpointVersion: envoy_config_trace_v3.ZipkinConfig_HTTP_JSON,
		})
		return &envoy_config_trace_v3.Tracing_Http{
			Name: "envoy.tracers.zipkin",
			ConfigType: &envoy_config_trace_v3.Tracing_Http_TypedConfig{
				TypedConfig: tracingTC,
			},
		}, nil
	default:
		return nil, nil
	}
}
