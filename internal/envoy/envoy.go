// Package envoy creates and configures an envoy server.
package envoy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_metrics_v3 "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	envoy_config_trace_v3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	"github.com/google/go-cmp/cmp"

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

type serverOptions struct {
	services       string
	logLevel       string
	tracingOptions trace.TracingOptions
}

// A Server is a pomerium proxy implemented via envoy.
type Server struct {
	wd  string
	cmd *exec.Cmd

	grpcPort, httpPort string
	envoyPath          string
	restartEpoch       int

	mu      sync.Mutex
	options serverOptions
}

// NewServer creates a new server with traffic routed by envoy.
func NewServer(src config.Source, grpcPort, httpPort string) (*Server, error) {
	wd := filepath.Join(os.TempDir(), workingDirectoryName)
	err := os.MkdirAll(wd, 0o755)
	if err != nil {
		return nil, fmt.Errorf("error creating temporary working directory for envoy: %w", err)
	}

	envoyPath, err := extractEmbeddedEnvoy()
	if err != nil {
		log.Warn().Err(err).Send()
		envoyPath = "envoy"
	}

	srv := &Server{
		wd:        wd,
		grpcPort:  grpcPort,
		httpPort:  httpPort,
		envoyPath: envoyPath,
	}

	src.OnConfigChange(srv.onConfigChange)
	srv.onConfigChange(src.GetConfig())

	return srv, nil
}

// Close kills any underlying envoy process.
func (srv *Server) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	var err error
	if srv.cmd != nil && srv.cmd.Process != nil {
		err = srv.cmd.Process.Kill()
		if err != nil {
			log.Error().Err(err).Str("service", "envoy").Msg("envoy: failed to kill process on close")
		}
		srv.cmd = nil
	}

	return err
}

func (srv *Server) onConfigChange(cfg *config.Config) {
	srv.update(cfg)
}

func (srv *Server) update(cfg *config.Config) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	tracingOptions, err := config.NewTracingOptions(cfg.Options)
	if err != nil {
		log.Error().Err(err).Str("service", "envoy").Msg("invalid tracing config")
		return
	}

	options := serverOptions{
		services:       cfg.Options.Services,
		logLevel:       firstNonEmpty(cfg.Options.ProxyLogLevel, cfg.Options.LogLevel, "debug"),
		tracingOptions: *tracingOptions,
	}

	if cmp.Equal(srv.options, options, cmp.AllowUnexported(serverOptions{})) {
		log.Debug().Str("service", "envoy").Msg("envoy: no config changes detected")
		return
	}
	srv.options = options

	if err := srv.writeConfig(); err != nil {
		log.Error().Err(err).Str("service", "envoy").Msg("envoy: failed to write envoy config")
		return
	}

	log.Info().Msg("envoy: starting envoy process")
	if err := srv.run(); err != nil {
		log.Error().Err(err).Str("service", "envoy").Msg("envoy: failed to run envoy process")
		return
	}
}

func (srv *Server) run() error {
	args := []string{
		"-c", configFileName,
		"--log-level", srv.options.logLevel,
		"--log-format", "[LOG_FORMAT]%l--%n--%v",
		"--log-format-escaped",
	}

	if baseID, ok := readBaseID(); ok {
		args = append(args, "--base-id", strconv.Itoa(baseID), "--restart-epoch", strconv.Itoa(srv.restartEpoch))
		srv.restartEpoch++ // start with epoch zero when we're a fresh pomerium process
	} else {
		args = append(args, "--use-dynamic-base-id", "--base-id-path", baseIDPath)
	}

	cmd := exec.Command(srv.envoyPath, args...) // #nosec
	cmd.Dir = srv.wd

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for envoy: %w", err)
	}
	go srv.handleLogs(stderr)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for envoy: %w", err)
	}
	go srv.handleLogs(stdout)

	// make sure envoy is killed if we're killed
	cmd.SysProcAttr = sysProcAttr

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting envoy: %w", err)
	}

	// release the previous process so we can hot-reload
	if srv.cmd != nil && srv.cmd.Process != nil {
		log.Info().Msg("envoy: releasing envoy process for hot-reload")
		err := srv.cmd.Process.Release()
		if err != nil {
			log.Warn().Err(err).Str("service", "envoy").Msg("envoy: failed to release envoy process for hot-reload")
		}
	}
	srv.cmd = cmd

	return nil
}

func (srv *Server) writeConfig() error {
	confBytes, err := srv.buildBootstrapConfig()
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(srv.wd, configFileName)
	log.Debug().Str("service", "envoy").Str("location", cfgPath).Msg("wrote config file to location")

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

	if err := srv.addTraceConfig(cfg); err != nil {
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
				FixedValue: telemetry.ServiceName(srv.options.services),
			},
		},
	}
	return cfg
}

func (srv *Server) addTraceConfig(bootCfg *envoy_config_bootstrap_v3.Bootstrap) error {
	if !srv.options.tracingOptions.Enabled() {
		return nil
	}

	// We only support zipkin in envoy currently
	if srv.options.tracingOptions.Provider != trace.ZipkinTracingProviderName {
		return nil
	}

	if srv.options.tracingOptions.ZipkinEndpoint.String() == "" {
		return fmt.Errorf("missing zipkin url")
	}

	// TODO the outbound header list should be configurable when this moves to
	// HTTPConnectionManager filters
	tracingTC, _ := ptypes.MarshalAny(
		&envoy_config_trace_v3.OpenCensusConfig{
			ZipkinExporterEnabled: true,
			ZipkinUrl:             srv.options.tracingOptions.ZipkinEndpoint.String(),
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

	bo := backoff.NewExponentialBackOff()

	s := bufio.NewReader(rc)
	for {
		ln, err := s.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				break
			}
			log.Error().Err(err).Msg("failed to read log")
			time.Sleep(bo.NextBackOff())
			continue
		}
		ln = strings.TrimRight(ln, "\r\n")
		bo.Reset()

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
