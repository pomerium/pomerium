// Package envoy creates and configures an envoy server.
package envoy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_metrics_v3 "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	envoy_config_trace_v3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/natefinch/atomic"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

const (
	workingDirectoryName = ".pomerium-envoy"
	configFileName       = "envoy-config.yaml"
)

// A Server is a pomerium proxy implemented via envoy.
type Server struct {
	wd  string
	cmd *exec.Cmd

	grpcPort, httpPort string
	opts               *config.Options
}

// NewServer creates a new server with traffic routed by envoy.
func NewServer(opts *config.Options, grpcPort, httpPort string) (*Server, error) {
	wd := filepath.Join(os.TempDir(), workingDirectoryName)
	err := os.MkdirAll(wd, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating temporary working directory for envoy: %w", err)
	}

	srv := &Server{
		wd:       wd,
		grpcPort: grpcPort,
		httpPort: httpPort,
		opts:     opts,
	}

	err = srv.writeConfig()
	if err != nil {
		return nil, fmt.Errorf("error writing initial envoy configuration: %w", err)
	}

	return srv, nil
}

// Run runs the server by extracting the embedded envoy and then executing it.
func (srv *Server) Run(ctx context.Context) error {
	envoyPath, err := extractEmbeddedEnvoy()
	if err != nil {
		log.Warn().Err(err).Send()
		envoyPath = "envoy"
	}

	srv.cmd = exec.CommandContext(ctx, envoyPath,
		"-c", configFileName,
		"--log-level", "trace",
		"--log-format", "[LOG_FORMAT]%l--%n--%v",
		"--log-format-escaped",
		"--disable-hot-restart",
	)
	srv.cmd.Dir = srv.wd

	stderr, err := srv.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for envoy: %w", err)
	}
	go srv.handleLogs(stderr)

	stdout, err := srv.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for envoy: %w", err)
	}
	go srv.handleLogs(stdout)

	// make sure envoy is killed if we're killed
	srv.cmd.SysProcAttr = sysProcAttr
	err = srv.cmd.Run()
	if err == nil {
		return errors.New("envoy exited without error")
	}
	return fmt.Errorf("envoy exited: %w", err)
}

func (srv *Server) writeConfig() error {
	confBytes, err := srv.buildBootstrapConfig()
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(srv.wd, configFileName)
	log.WithLevel(zerolog.DebugLevel).Str("service", "envoy").Str("location", cfgPath).Msg("wrote config file to location")

	return atomic.WriteFile(cfgPath, bytes.NewReader(confBytes))
}

func (srv *Server) buildBootstrapConfig() ([]byte, error) {

	nodeCfg := &envoy_config_core_v3.Node{
		Id:      "proxy",
		Cluster: "proxy",
	}

	adminCfg := &envoy_config_bootstrap_v3.Admin{
		AccessLogPath: "/tmp/admin_access.log",
		Address: &envoy_config_core_v3.Address{
			Address: &envoy_config_core_v3.Address_SocketAddress{
				SocketAddress: &envoy_config_core_v3.SocketAddress{
					Address: "127.0.0.1",
					PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
						PortValue: 9901,
					},
				},
			},
		},
	}

	dynamicCfg := &envoy_config_bootstrap_v3.Bootstrap_DynamicResources{
		AdsConfig: &envoy_config_core_v3.ApiConfigSource{
			ApiType:             envoy_config_core_v3.ApiConfigSource_ApiType(envoy_config_core_v3.ApiConfigSource_ApiType_value["GRPC"]),
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
	}

	controlPlanePort, err := strconv.Atoi(srv.grpcPort)
	if err != nil {
		return nil, fmt.Errorf("invalid control plane port: %w", err)
	}

	controlPlaneEndpoint := &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
		Endpoint: &envoy_config_endpoint_v3.Endpoint{
			Address: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address: "127.0.0.1",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: uint32(controlPlanePort),
						},
					},
				},
			},
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
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{},
	}

	staticCfg := &envoy_config_bootstrap_v3.Bootstrap_StaticResources{
		Clusters: []*envoy_config_cluster_v3.Cluster{
			controlPlaneCluster,
		},
	}

	cfg := &envoy_config_bootstrap_v3.Bootstrap{
		Node:             nodeCfg,
		Admin:            adminCfg,
		DynamicResources: dynamicCfg,
		StaticResources:  staticCfg,
		StatsConfig:      srv.buildStatsConfig(),
	}

	traceOpts, err := config.NewTracingOptions(srv.opts)
	if err != nil {
		return nil, fmt.Errorf("invalid tracing config: %w", err)
	}

	if err := srv.addTraceConfig(traceOpts, cfg); err != nil {
		return nil, fmt.Errorf("failed to add tracing config: %w", err)
	}

	jsonBytes, err := protojson.Marshal(proto.MessageV2(cfg))
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

func (srv *Server) buildStatsConfig() *envoy_config_metrics_v3.StatsConfig {
	cfg := &envoy_config_metrics_v3.StatsConfig{}

	cfg.StatsTags = []*envoy_config_metrics_v3.TagSpecifier{
		{
			TagName: "service",
			TagValue: &envoy_config_metrics_v3.TagSpecifier_FixedValue{
				FixedValue: telemetry.ServiceName(srv.opts.Services),
			},
		},
	}
	return cfg
}

func (srv *Server) addTraceConfig(traceOpts *config.TracingOptions, bootCfg *envoy_config_bootstrap_v3.Bootstrap) error {

	if !traceOpts.Enabled() {
		return nil
	}

	// We only support zipkin in envoy currently
	if traceOpts.Provider != trace.ZipkinTracingProviderName {
		return nil
	}

	if traceOpts.ZipkinEndpoint.String() == "" {
		return fmt.Errorf("missing zipkin url")
	}

	// TODO the outbound header list should be configurable when this moves to
	// HTTPConnectionManager filters
	tracingTC, _ := ptypes.MarshalAny(
		&envoy_config_trace_v3.OpenCensusConfig{
			ZipkinExporterEnabled: true,
			ZipkinUrl:             traceOpts.ZipkinEndpoint.String(),
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

	tracingCfg := &envoy_config_trace_v3.Tracing{
		Http: &envoy_config_trace_v3.Tracing_Http{
			Name: "envoy.tracers.opencensus",
			ConfigType: &envoy_config_trace_v3.Tracing_Http_TypedConfig{
				TypedConfig: tracingTC,
			},
		},
	}
	bootCfg.Tracing = tracingCfg

	return nil
}

var fileNameAndNumberRE = regexp.MustCompile(`^(\[[a-zA-Z0-9/-_.]+:[0-9]+])\s(.*)$`)

func (srv *Server) parseLog(line string) (name string, logLevel string, msg string) {
	// format: [LOG_FORMAT]level--name--message
	// message is c-escaped
	parts := strings.SplitN(line, "--", 3)
	if len(parts) == 3 {
		logLevel = strings.TrimPrefix(parts[0], "[LOG_FORMAT]")
		name = parts[1]
		msg = parts[2]
	}
	return
}

func (srv *Server) handleLogs(rc io.ReadCloser) {
	defer rc.Close()
	s := bufio.NewReader(rc)
	for {
		ln, err := s.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Error().Err(err).Msg("failed to read log")
			continue
		}
		ln = strings.TrimRight(ln, "\r\n")

		name, logLevel, msg := srv.parseLog(ln)
		if name == "" {
			name = "envoy"
		}
		lvl := zerolog.DebugLevel
		if x, err := zerolog.ParseLevel(logLevel); err == nil {
			lvl = x
		}
		if msg == "" {
			msg = ln
		}

		msg = fileNameAndNumberRE.ReplaceAllString(msg, "\"$2\"")
		if s, err := strconv.Unquote(msg); err == nil {
			msg = s
		}

		// ignore empty messages
		if msg == "" {
			continue
		}

		log.WithLevel(lvl).
			Str("service", "envoy").
			Str("name", name).
			Msg(msg)
	}
}
