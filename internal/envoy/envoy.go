// Package envoy creates and configures an envoy server.
package envoy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/natefinch/atomic"
	"github.com/rs/zerolog"
	"github.com/shirou/gopsutil/v3/process"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

const (
	workingDirectoryName = ".pomerium-envoy"
	configFileName       = "envoy-config.yaml"
)

// Checksum is the embedded envoy binary checksum. This value is populated by `make build`.
var Checksum string

type serverOptions struct {
	services       string
	logLevel       string
	tracingOptions trace.TracingOptions
}

// A Server is a pomerium proxy implemented via envoy.
type Server struct {
	wd  string
	cmd *exec.Cmd

	builder            *envoyconfig.Builder
	grpcPort, httpPort string
	envoyPath          string

	monitorProcessCancel context.CancelFunc

	mu      sync.Mutex
	options serverOptions
}

// NewServer creates a new server with traffic routed by envoy.
func NewServer(ctx context.Context, src config.Source, grpcPort, httpPort string, builder *envoyconfig.Builder) (*Server, error) {
	wd := filepath.Join(os.TempDir(), workingDirectoryName)
	err := os.MkdirAll(wd, embeddedEnvoyPermissions)
	if err != nil {
		return nil, fmt.Errorf("error creating temporary working directory for envoy: %w", err)
	}

	envoyPath, err := extractEmbeddedEnvoy(ctx)
	if err != nil {
		log.Warn(ctx).Err(err).Send()
		envoyPath = "envoy"
	}

	fullEnvoyPath, err := exec.LookPath(envoyPath)
	if err != nil {
		return nil, fmt.Errorf("no envoy binary found: %w", err)
	}

	// Checksum is written at build time, if it's not empty we verify the binary
	if Checksum != "" {
		bs, err := ioutil.ReadFile(fullEnvoyPath)
		if err != nil {
			return nil, fmt.Errorf("error reading envoy binary for checksum verification: %w", err)
		}
		h := sha256.New()
		h.Write(bs)
		s := hex.EncodeToString(h.Sum(nil))
		if Checksum != s {
			return nil, fmt.Errorf("invalid envoy binary, expected %s but got %s", Checksum, s)
		}
	} else {
		log.Info(ctx).Msg("no checksum defined, envoy binary will not be verified!")
	}

	srv := &Server{
		wd:        wd,
		builder:   builder,
		grpcPort:  grpcPort,
		httpPort:  httpPort,
		envoyPath: envoyPath,

		monitorProcessCancel: func() {},
	}
	go srv.runProcessCollector(ctx)

	src.OnConfigChange(ctx, srv.onConfigChange)
	srv.onConfigChange(ctx, src.GetConfig())

	log.Info(ctx).
		Str("path", envoyPath).
		Str("checksum", Checksum).
		Msg("running envoy")

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
			log.Error(context.TODO()).Err(err).Str("service", "envoy").Msg("envoy: failed to kill process on close")
		}
		srv.cmd = nil
	}

	return err
}

func (srv *Server) onConfigChange(ctx context.Context, cfg *config.Config) {
	srv.update(ctx, cfg)
}

func (srv *Server) update(ctx context.Context, cfg *config.Config) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	tracingOptions, err := config.NewTracingOptions(cfg.Options)
	if err != nil {
		log.Error(ctx).Err(err).Str("service", "envoy").Msg("invalid tracing config")
		return
	}

	options := serverOptions{
		services:       cfg.Options.Services,
		logLevel:       firstNonEmpty(cfg.Options.ProxyLogLevel, cfg.Options.LogLevel, "debug"),
		tracingOptions: *tracingOptions,
	}

	if cmp.Equal(srv.options, options, cmp.AllowUnexported(serverOptions{})) {
		log.Debug(ctx).Str("service", "envoy").Msg("envoy: no config changes detected")
		return
	}
	srv.options = options

	log.Info(ctx).Msg("envoy: starting envoy process")
	if err := srv.run(ctx, cfg); err != nil {
		log.Error(ctx).Err(err).Str("service", "envoy").Msg("envoy: failed to run envoy process")
		return
	}
}

func (srv *Server) run(ctx context.Context, cfg *config.Config) error {
	// cancel any process monitor since we will be killing the previous process
	srv.monitorProcessCancel()

	if err := srv.writeConfig(ctx, cfg); err != nil {
		log.Error(ctx).Err(err).Str("service", "envoy").Msg("envoy: failed to write envoy config")
		return err
	}

	args := []string{
		"-c", configFileName,
		"--log-level", srv.options.logLevel,
		"--log-format", "[LOG_FORMAT]%l--%n--%v",
		"--log-format-escaped",
	}

	exePath, args := srv.prepareRunEnvoyCommand(ctx, args)
	cmd := exec.Command(exePath, args...)
	cmd.Dir = srv.wd

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for envoy: %w", err)
	}
	go srv.handleLogs(ctx, stderr)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for envoy: %w", err)
	}
	go srv.handleLogs(ctx, stdout)

	// make sure envoy is killed if we're killed
	cmd.SysProcAttr = sysProcAttr

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting envoy: %w", err)
	}
	// call Wait to avoid zombie processes
	go func() { _ = cmd.Wait() }()

	// monitor the process so we exit if it prematurely exits
	var monitorProcessCtx context.Context
	monitorProcessCtx, srv.monitorProcessCancel = context.WithCancel(context.Background())
	go srv.monitorProcess(monitorProcessCtx, int32(cmd.Process.Pid))

	srv.cmd = cmd

	return nil
}

func (srv *Server) writeConfig(ctx context.Context, cfg *config.Config) error {
	confBytes, err := srv.buildBootstrapConfig(cfg)
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(srv.wd, configFileName)
	log.Debug(ctx).Str("service", "envoy").Str("location", cfgPath).Msg("wrote config file to location")

	return atomic.WriteFile(cfgPath, bytes.NewReader(confBytes))
}

func (srv *Server) buildBootstrapConfig(cfg *config.Config) ([]byte, error) {
	nodeCfg := &envoy_config_core_v3.Node{
		Id:      "proxy",
		Cluster: "proxy",
	}

	adminCfg, err := srv.builder.BuildBootstrapAdmin(cfg)
	if err != nil {
		return nil, err
	}

	dynamicCfg := &envoy_config_bootstrap_v3.Bootstrap_DynamicResources{
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
	}

	staticCfg, err := srv.builder.BuildBootstrapStaticResources(cfg)
	if err != nil {
		return nil, err
	}

	statsCfg, err := srv.builder.BuildBootstrapStatsConfig(cfg)
	if err != nil {
		return nil, err
	}

	bootstrapCfg := &envoy_config_bootstrap_v3.Bootstrap{
		Node:             nodeCfg,
		Admin:            adminCfg,
		DynamicResources: dynamicCfg,
		StaticResources:  staticCfg,
		StatsConfig:      statsCfg,
	}

	jsonBytes, err := protojson.Marshal(proto.MessageV2(bootstrapCfg))
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
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

func (srv *Server) handleLogs(ctx context.Context, rc io.ReadCloser) {
	defer rc.Close()

	l := log.With().Str("service", "envoy").Logger()
	bo := backoff.NewExponentialBackOff()

	s := bufio.NewReader(rc)
	for {
		ln, err := s.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				break
			}
			log.Error(ctx).Err(err).Msg("failed to read log")
			time.Sleep(bo.NextBackOff())
			continue
		}
		ln = strings.TrimRight(ln, "\r\n")
		bo.Reset()

		name, logLevel, msg := srv.parseLog(ln)
		if name == "" {
			name = "envoy"
		}

		lvl := zerolog.ErrorLevel
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

		l.WithLevel(lvl).
			Str("name", name).
			Msg(msg)
	}
}

func (srv *Server) monitorProcess(ctx context.Context, pid int32) {
	log.Info(ctx).
		Int32("pid", pid).
		Msg("envoy: start monitoring subprocess")

	proc, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		log.Fatal().Err(err).
			Int32("pid", pid).
			Msg("envoy: error retrieving subprocess information")
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		// wait for the next tick
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		running, err := proc.IsRunningWithContext(ctx)
		if err != nil {
			log.Error(ctx).Err(err).
				Int32("pid", pid).
				Msg("envoy: error retrieving subprocess status")
		} else if !running {
			log.Fatal().Err(err).
				Int32("pid", pid).
				Msg("envoy: subprocess exited")
		}
	}
}
