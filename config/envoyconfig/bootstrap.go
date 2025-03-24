package envoyconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_metrics_v3 "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	envoy_config_overload_v3 "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	envoy_extensions_access_loggers_file_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	envoy_extensions_resource_monitors_downstream_connections_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/otelconfig"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
)

const maxActiveDownstreamConnections = 50000

var (
	envoyAdminAddressSockName = "pomerium-envoy-admin.sock"
	envoyAdminClusterName     = "pomerium-envoy-admin"

	socketMode = 0o600
)

// BuildBootstrap builds the bootstrap config.
func (b *Builder) BuildBootstrap(
	ctx context.Context,
	cfg *config.Config,
	fullyStatic bool,
) (bootstrap *envoy_config_bootstrap_v3.Bootstrap, err error) {
	ctx, span := trace.Continue(ctx, "envoyconfig.Builder.BuildBootstrap")
	defer span.End()

	bootstrap = new(envoy_config_bootstrap_v3.Bootstrap)

	bootstrap.Admin, err = b.BuildBootstrapAdmin(cfg)
	if err != nil {
		return nil, fmt.Errorf("error building bootstrap admin: %w", err)
	}

	bootstrap.DynamicResources, err = b.BuildBootstrapDynamicResources(cfg, fullyStatic)
	if err != nil {
		return nil, fmt.Errorf("error building bootstrap dynamic resources: %w", err)
	}

	bootstrap.LayeredRuntime, err = b.BuildBootstrapLayeredRuntime(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error building bootstrap layered runtime: %w", err)
	}

	bootstrap.Node = &envoy_config_core_v3.Node{
		Id:      telemetry.ServiceName(cfg.Options.Services),
		Cluster: telemetry.ServiceName(cfg.Options.Services),
	}

	bootstrap.StaticResources, err = b.BuildBootstrapStaticResources(ctx, cfg, fullyStatic)
	if err != nil {
		return nil, fmt.Errorf("error building bootstrap static resources: %w", err)
	}

	bootstrap.StatsConfig, err = b.BuildBootstrapStatsConfig(cfg)
	if err != nil {
		return nil, err
	}

	bootstrap.OverloadManager = &envoy_config_overload_v3.OverloadManager{
		ResourceMonitors: []*envoy_config_overload_v3.ResourceMonitor{{
			Name: "envoy.resource_monitors.global_downstream_max_connections",
			ConfigType: &envoy_config_overload_v3.ResourceMonitor_TypedConfig{
				TypedConfig: marshalAny(&envoy_extensions_resource_monitors_downstream_connections_v3.DownstreamConnectionsConfig{
					MaxActiveDownstreamConnections: maxActiveDownstreamConnections,
				}),
			},
		}},
	}

	return bootstrap, nil
}

// BuildBootstrapAdmin builds the admin config for the envoy bootstrap.
func (b *Builder) BuildBootstrapAdmin(cfg *config.Config) (admin *envoy_config_bootstrap_v3.Admin, err error) {
	admin = &envoy_config_bootstrap_v3.Admin{
		ProfilePath: cfg.Options.EnvoyAdminProfilePath,
	}

	admin.Address = &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_Pipe{
			Pipe: &envoy_config_core_v3.Pipe{
				Path: filepath.Join(os.TempDir(), envoyAdminAddressSockName),
				Mode: uint32(socketMode),
			},
		},
	}

	if cfg.Options.EnvoyAdminAccessLogPath != os.DevNull && cfg.Options.EnvoyAdminAccessLogPath != "" {
		tc := marshalAny(&envoy_extensions_access_loggers_file_v3.FileAccessLog{
			Path: cfg.Options.EnvoyAdminAccessLogPath,
		})
		admin.AccessLog = append(admin.AccessLog, &envoy_config_accesslog_v3.AccessLog{
			Name:       "envoy.access_loggers.file",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{TypedConfig: tc},
		})
	}

	return admin, nil
}

// BuildBootstrapDynamicResources builds the dynamic resources for the envoy bootstrap.
func (b *Builder) BuildBootstrapDynamicResources(
	_ *config.Config,
	fullyStatic bool,
) (dynamicResources *envoy_config_bootstrap_v3.Bootstrap_DynamicResources, err error) {
	if fullyStatic {
		return nil, nil
	}
	return &envoy_config_bootstrap_v3.Bootstrap_DynamicResources{
		AdsConfig: &envoy_config_core_v3.ApiConfigSource{
			ApiType:             envoy_config_core_v3.ApiConfigSource_ApiType(envoy_config_core_v3.ApiConfigSource_ApiType_value["DELTA_GRPC"]),
			TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
			GrpcServices: []*envoy_config_core_v3.GrpcService{
				{
					TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
							ClusterName: "pomerium-control-plane-grpc",
						},
					},
				},
			},
		},
		LdsConfig: &envoy_config_core_v3.ConfigSource{
			ResourceApiVersion:    envoy_config_core_v3.ApiVersion_V3,
			ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{},
		},
		CdsConfig: &envoy_config_core_v3.ConfigSource{
			ResourceApiVersion:    envoy_config_core_v3.ApiVersion_V3,
			ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{},
		},
	}, nil
}

// BuildBootstrapLayeredRuntime builds the layered runtime for the envoy bootstrap.
func (b *Builder) BuildBootstrapLayeredRuntime(ctx context.Context, cfg *config.Config) (*envoy_config_bootstrap_v3.LayeredRuntime, error) {
	flushInterval := otelconfig.DefaultScheduleDelay
	minFlushSpans := int32(otelconfig.DefaultMaxExportBatchSize)
	if cfg.Options != nil {
		if cfg.Options.Tracing.OtelBspScheduleDelay != nil {
			flushInterval = max(otelconfig.MinimumScheduleDelay, time.Duration(*cfg.Options.Tracing.OtelBspScheduleDelay))
		}
		if cfg.Options.Tracing.OtelBspMaxExportBatchSize != nil {
			minFlushSpans = max(otelconfig.MinimumMaxExportBatchSize, *cfg.Options.Tracing.OtelBspMaxExportBatchSize)
		}
	}
	if trace.DebugFlagsFromContext(ctx).Check(trace.EnvoyFlushEverySpan) {
		flushInterval = 24 * time.Hour
		minFlushSpans = 1
	}
	layer, err := structpb.NewStruct(map[string]any{
		"re2": map[string]any{
			"max_program_size": map[string]any{
				"error_level": 1024 * 1024,
				"warn_level":  1024,
			},
		},
		"tracing": map[string]any{
			"opentelemetry": map[string]any{
				"flush_interval_ms": flushInterval.Milliseconds(),
				// Note: for most requests, envoy generates 3 spans:
				// - ingress (downstream->envoy)
				// - ext_authz check request (envoy->pomerium)
				// - egress (envoy->upstream)
				// Some requests only generate 2 spans, e.g. if there is no upstream
				// request made or auth fails.
				"min_flush_spans": minFlushSpans,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("envoyconfig: failed to create layered runtime layer: %w", err)
	}

	return &envoy_config_bootstrap_v3.LayeredRuntime{
		Layers: []*envoy_config_bootstrap_v3.RuntimeLayer{
			{
				Name: "static_layer_0",
				LayerSpecifier: &envoy_config_bootstrap_v3.RuntimeLayer_StaticLayer{
					StaticLayer: layer,
				},
			},
		},
	}, nil
}

// BuildBootstrapStaticResources builds the static resources for the envoy bootstrap. It includes the control plane
// cluster.
func (b *Builder) BuildBootstrapStaticResources(
	ctx context.Context,
	cfg *config.Config,
	fullyStatic bool,
) (staticResources *envoy_config_bootstrap_v3.Bootstrap_StaticResources, err error) {
	ctx, span := trace.Continue(ctx, "envoyconfig.Builder.BuildBootstrapStaticResources")
	defer span.End()

	staticResources = new(envoy_config_bootstrap_v3.Bootstrap_StaticResources)

	if fullyStatic {
		staticResources.Clusters, err = b.BuildClusters(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("error building clusters: %w", err)
		}

		staticResources.Listeners, err = b.BuildListeners(ctx, cfg, fullyStatic)
		if err != nil {
			return nil, fmt.Errorf("error building listeners: %w", err)
		}

		return staticResources, nil
	}

	grpcAddr, err := parseAddress(b.localGRPCAddress)
	if err != nil {
		return nil, fmt.Errorf("envoyconfig: invalid local gRPC address: %w", err)
	}

	controlPlaneEndpoint := &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
		Endpoint: &envoy_config_endpoint_v3.Endpoint{
			Address: grpcAddr,
		},
	}

	controlPlaneCluster := &envoy_config_cluster_v3.Cluster{
		Name: "pomerium-control-plane-grpc",
		ConnectTimeout: &durationpb.Duration{
			Seconds: 5,
		},
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_STATIC,
		},
		LbPolicy: envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "pomerium-control-plane-grpc",
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
						{
							HostIdentifier: controlPlaneEndpoint,
						},
					},
				},
			},
		},
		TypedExtensionProtocolOptions: buildTypedExtensionProtocolOptions(nil, upstreamProtocolHTTP2, Keepalive(false)),
	}

	staticResources.Clusters = append(staticResources.Clusters, controlPlaneCluster)

	return staticResources, nil
}

// BuildBootstrapStatsConfig builds a the stats config the envoy bootstrap.
func (b *Builder) BuildBootstrapStatsConfig(cfg *config.Config) (*envoy_config_metrics_v3.StatsConfig, error) {
	statsCfg := &envoy_config_metrics_v3.StatsConfig{}
	statsCfg.StatsTags = []*envoy_config_metrics_v3.TagSpecifier{{
		TagName: "service",
		TagValue: &envoy_config_metrics_v3.TagSpecifier_FixedValue{
			FixedValue: telemetry.ServiceName(cfg.Options.Services),
		},
	}}
	return statsCfg, nil
}
