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
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/natefinch/atomic"
	"github.com/rs/zerolog"
	"github.com/shirou/gopsutil/v3/process"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/envoy/files"
)

const (
	configFileName = "envoy-config.yaml"
)

type serverOptions struct {
	services string
	logLevel config.LogLevel
}

// A Server is a pomerium proxy implemented via envoy.
type Server struct {
	wd  string
	cmd *exec.Cmd

	builder            *envoyconfig.Builder
	resourceMonitor    ResourceMonitor
	grpcPort, httpPort string
	envoyPath          string

	monitorProcessCancel context.CancelFunc

	mu      sync.Mutex
	options serverOptions
}

// NewServer creates a new server with traffic routed by envoy.
func NewServer(ctx context.Context, src config.Source, builder *envoyconfig.Builder) (*Server, error) {
	if err := preserveRlimitNofile(); err != nil {
		log.Debug(ctx).Err(err).Msg("couldn't preserve RLIMIT_NOFILE before starting Envoy")
	}

	envoyPath, err := Extract()
	if err != nil {
		return nil, fmt.Errorf("extracting envoy: %w", err)
	}

	srv := &Server{
		wd:        path.Dir(envoyPath),
		builder:   builder,
		grpcPort:  src.GetConfig().GRPCPort,
		httpPort:  src.GetConfig().HTTPPort,
		envoyPath: envoyPath,

		monitorProcessCancel: func() {},
	}
	go srv.runProcessCollector(ctx)

	if rm, err := NewSharedResourceMonitor(ctx, src, srv.wd); err == nil {
		srv.resourceMonitor = rm
	} else {
		log.Ctx(ctx).Error().Err(err).Str("service", "envoy").Msg("not starting resource monitor")
	}

	src.OnConfigChange(ctx, srv.onConfigChange)
	srv.onConfigChange(ctx, src.GetConfig())

	log.Debug(ctx).
		Str("path", envoyPath).
		Str("checksum", files.Checksum()).
		Msg("running envoy")

	return srv, nil
}

// Close kills any underlying envoy process.
func (srv *Server) Close() error {
	srv.monitorProcessCancel()

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

func (srv *Server) onConfigChange(ctx context.Context, cfg *config.Config) {
	srv.update(ctx, cfg)
}

func (srv *Server) update(ctx context.Context, cfg *config.Config) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	options := serverOptions{
		services: cfg.Options.Services,
		logLevel: firstNonEmpty(cfg.Options.ProxyLogLevel, cfg.Options.LogLevel, config.LogLevelDebug),
	}

	if cmp.Equal(srv.options, options, cmp.AllowUnexported(serverOptions{})) {
		log.Debug(ctx).Str("service", "envoy").Msg("envoy: no config changes detected")
		return
	}
	srv.options = options

	log.Debug(ctx).Msg("envoy: starting envoy process")
	if err := srv.run(ctx, cfg); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("service", "envoy").Msg("envoy: failed to run envoy process")
		return
	}
}

func (srv *Server) run(ctx context.Context, cfg *config.Config) error {
	// cancel any process monitor since we will be killing the previous process
	srv.monitorProcessCancel()

	if err := srv.writeConfig(ctx, cfg); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("service", "envoy").Msg("envoy: failed to write envoy config")
		return err
	}

	args := []string{
		"-c", configFileName,
		"--log-level", srv.options.logLevel.ToEnvoy(),
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
		return fmt.Errorf("error creating stdout pipe for envoy: %w", err)
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

	if srv.resourceMonitor != nil {
		log.Debug(ctx).Str("service", "envoy").Msg("starting resource monitor")
		go func() {
			err := srv.resourceMonitor.Run(ctx, cmd.Process.Pid)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					log.Debug(ctx).Err(err).Str("service", "envoy").Msg("resource monitor stopped")
				} else {
					log.Ctx(ctx).Error().Err(err).Str("service", "envoy").Msg("resource monitor exited with error")
				}
			}
		}()
	}
	srv.cmd = cmd

	return nil
}

func (srv *Server) writeConfig(ctx context.Context, cfg *config.Config) error {
	confBytes, err := srv.buildBootstrapConfig(ctx, cfg)
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(srv.wd, configFileName)
	log.Debug(ctx).Str("service", "envoy").Str("location", cfgPath).Msg("wrote config file to location")

	return atomic.WriteFile(cfgPath, bytes.NewReader(confBytes))
}

func (srv *Server) buildBootstrapConfig(ctx context.Context, cfg *config.Config) ([]byte, error) {
	bootstrapCfg, err := srv.builder.BuildBootstrap(ctx, cfg, false)
	if err != nil {
		return nil, err
	}
	if srv.resourceMonitor != nil {
		srv.resourceMonitor.ApplyBootstrapConfig(bootstrapCfg)
	}

	jsonBytes, err := protojson.Marshal(bootstrapCfg)
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
			log.Ctx(ctx).Error().Err(err).Msg("failed to read log")
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
		if lvl == zerolog.InfoLevel {
			lvl = zerolog.DebugLevel
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
	log.Debug(ctx).
		Int32("pid", pid).
		Msg("envoy: start monitoring subprocess")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		exists, err := process.PidExistsWithContext(ctx, pid)
		if err != nil {
			log.Fatal().Err(err).
				Int32("pid", pid).
				Msg("envoy: error retrieving subprocess information")
		} else if !exists {
			log.Fatal().Err(err).
				Int32("pid", pid).
				Msg("envoy: subprocess exited")
		}

		// wait for the next tick
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func preserveRlimitNofile() error {
	// Go raises the "max open files" soft limit to match the hard limit for
	// itself, but has special logic to reset the original soft limit before
	// forking a child process. This logic does not apply if the file limit is
	// set explicitly. This pair of Getrlimit / Setrlimit calls is intended to
	// (1) preserve the default Go limit behavior for ourselves, and
	// (2) keep these same limits when launching Envoy.
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return err
	}
	return syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
}
