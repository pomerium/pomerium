// Package envoy creates and configures an envoy server.
package envoy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	stdatomic "sync/atomic"
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
	"github.com/pomerium/pomerium/pkg/health"
)

const (
	configFileName = "envoy-config.yaml"
)

// A Server is a pomerium proxy implemented via envoy.
type Server struct {
	ServerOptions
	wd        string
	cmd       *exec.Cmd
	cmdExited chan struct{}
	closing   stdatomic.Bool

	builder            *envoyconfig.Builder
	resourceMonitor    ResourceMonitor
	grpcPort, httpPort string
	envoyPath          string

	monitorProcessCancel context.CancelFunc

	mu        sync.Mutex
	shutdownC chan error
}

type ServerOptions struct {
	extraEnvVars    []string
	logLevel        config.LogLevel
	exitGracePeriod time.Duration
}

func (o *ServerOptions) ExitGracePeriod() time.Duration {
	return o.exitGracePeriod
}

type ServerOption func(*ServerOptions)

func (o *ServerOptions) apply(opts ...ServerOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithExtraEnvVars(extraEnvVars ...string) ServerOption {
	return func(o *ServerOptions) {
		o.extraEnvVars = append(o.extraEnvVars, extraEnvVars...)
	}
}

func WithExitGracePeriod(duration time.Duration) ServerOption {
	return func(o *ServerOptions) {
		o.exitGracePeriod = duration
	}
}

// NewServer creates a new server with traffic routed by envoy.
func NewServer(
	ctx context.Context,
	shutdown chan error,
	src config.Source,
	builder *envoyconfig.Builder,
	opts ...ServerOption,
) (*Server, error) {
	options := ServerOptions{}
	options.apply(opts...)

	if err := preserveRlimitNofile(); err != nil {
		log.Ctx(ctx).Debug().Err(err).Msg("couldn't preserve RLIMIT_NOFILE before starting Envoy")
	}

	envoyPath, err := Extract()
	if err != nil {
		return nil, fmt.Errorf("extracting envoy: %w", err)
	}

	srv := &Server{
		ServerOptions:        options,
		wd:                   path.Dir(envoyPath),
		builder:              builder,
		grpcPort:             src.GetConfig().GRPCPort,
		httpPort:             src.GetConfig().HTTPPort,
		envoyPath:            envoyPath,
		shutdownC:            shutdown,
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

	log.Ctx(ctx).Debug().
		Str("path", envoyPath).
		Str("checksum", files.Checksum()).
		Msg("running envoy")

	return srv, nil
}

func (srv *Server) envoyAdminClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return net.Dial("unix", filepath.Join(os.TempDir(), "pomerium-envoy-admin.sock"))
			},
		},
	}
}

func (srv *Server) Drain() error {
	u := &url.URL{
		Scheme: "http",
		Host:   "unix",
		Path:   ("/drain_listeners"),
	}
	client := srv.envoyAdminClient()

	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Add("graceful", "")
	req.URL.RawQuery = q.Encode()
	log.Debug().Msg("requesting graceful drain from envoy")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected admin drain response : %d", resp.StatusCode)
	}
	log.Debug().Msg("request to gracefully drain envoy succeeded")

	return nil
}

func (srv *Server) exitGracePeriodOrDefault() time.Duration {
	if srv.exitGracePeriod == 0 {
		// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/draining
		// https://www.envoyproxy.io/docs/envoy/latest/operations/cli#cmdoption-drain-time-s
		return time.Second * 600
	}
	return srv.exitGracePeriod
}

// Close attempts to gracefully shut down a running envoy server. If envoy
// does not exit within the defined grace period, it will be killed. Server
// cannot be used again after Close is called.
func (srv *Server) Close() error {
	if !srv.closing.CompareAndSwap(false, true) {
		return nil
	}
	health.ReportTerminating(health.EnvoyServer)
	defer close(srv.shutdownC)
	srv.monitorProcessCancel()

	srv.mu.Lock()
	defer srv.mu.Unlock()

	var err error
	if srv.cmd != nil && srv.cmd.Process != nil {
		if err := srv.Drain(); err != nil {
			log.Error().Err(err).Msg("failed to request graceful drain from envoy")
		}
		log.Debug().Int("exit-grace-period-seconds", int(srv.exitGracePeriod.Seconds())).Msg("requesting envoy to shutdown gracefully")
		if srv.exitGracePeriodOrDefault() > 0 {
			_ = srv.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-srv.cmdExited:
				return nil
			case <-time.After(srv.exitGracePeriodOrDefault()):
			}
		}
		err = srv.cmd.Process.Kill()
		if err != nil {
			log.Error().Err(err).Str("service", "envoy").Msg("envoy: failed to kill process on close")
		} else {
			<-srv.cmdExited
		}

		srv.cmd = nil
	}
	// envoy cmd was either already not running or had to be killed after the grace period
	termErr := errors.Join(fmt.Errorf("envoy forcefully terminated"), err)
	health.ReportError(health.EnvoyServer, termErr)
	srv.shutdownC <- termErr
	return err
}

func (srv *Server) onConfigChange(ctx context.Context, cfg *config.Config) {
	if srv.closing.Load() {
		// do not attempt to update the configuration after Close is called
		return
	}
	srv.update(ctx, cfg)
}

func (srv *Server) update(ctx context.Context, cfg *config.Config) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	opts := srv.ServerOptions
	// log level is managed via config
	opts.logLevel = firstNonEmpty(cfg.Options.ProxyLogLevel, cfg.Options.LogLevel, config.LogLevelDebug)

	if cmp.Equal(srv.ServerOptions, opts, cmp.AllowUnexported(ServerOptions{})) {
		log.Ctx(ctx).Debug().Str("service", "envoy").Msg("envoy: no config changes detected")
		return
	}
	srv.ServerOptions = opts

	log.Ctx(ctx).Debug().Msg("envoy: starting envoy process")
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
		"--log-level", srv.logLevel.ToEnvoy(),
		"--log-format", "[LOG_FORMAT]%l--%n--%v",
		"--log-format-escaped",
	}

	// By default, envoy will use a concurrency set to the number of cores available on a machine.
	// However when a CPU quota is set on the process (for example with a CPU limit in kubernetes)
	// this can result in an excess number of workers given how much CPU is allocated to the process.
	//
	// Since we rely on automaxprocs to set the GOMAXPROCS based on the CPU quota, we can rely on that
	// same behavior for envoy.
	if cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagSetEnvoyConcurrencyToGoMaxProcs) {
		args = append(args, "--concurrency", strconv.Itoa(runtime.GOMAXPROCS(0)))
	}

	exePath, args := srv.prepareRunEnvoyCommand(ctx, args)
	cmd := exec.Command(exePath, args...)
	cmd.Dir = srv.wd
	cmd.Env = append(cmd.Env, srv.extraEnvVars...)

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
		health.ReportError(health.EnvoyServer, fmt.Errorf("error starting envoy : %w", err))
		return fmt.Errorf("error starting envoy: %w", err)
	}
	// call Wait to avoid zombie processes
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		_ = cmd.Wait()
	}()
	go func() {
		srv.readiness(ctx, exited)
		log.Ctx(ctx).Debug().Msg("readiness check stopped")
	}()

	// monitor the process so we exit if it prematurely exits
	var monitorProcessCtx context.Context
	monitorProcessCtx, srv.monitorProcessCancel = context.WithCancel(context.WithoutCancel(ctx))

	go func() {
		pid := cmd.Process.Pid
		err := srv.monitorProcess(monitorProcessCtx, int32(pid))
		if err != nil && ctx.Err() == nil && !srv.closing.Load() {
			// If the envoy subprocess exits and ctx is not done (or waiting for envoy
			// to gracefully stop), issue a fatal error. If ctx is done, the server is
			// already exiting, and envoy is expected to be stopped along with it.
			log.Ctx(ctx).
				Fatal().
				Int("pid", pid).
				Err(err).
				Send()
		}
		log.Ctx(ctx).
			Debug().
			Int("pid", pid).
			Err(ctx.Err()).
			Msg("envoy process monitor stopped")
	}()

	if srv.resourceMonitor != nil {
		log.Ctx(ctx).Debug().Str("service", "envoy").Msg("starting resource monitor")
		go func() {
			err := srv.resourceMonitor.Run(ctx, cmd.Process.Pid)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					log.Ctx(ctx).Debug().Err(err).Str("service", "envoy").Msg("resource monitor stopped")
				} else {
					log.Ctx(ctx).Error().Err(err).Str("service", "envoy").Msg("resource monitor exited with error")
				}
			}
		}()
	}
	srv.cmd = cmd
	srv.cmdExited = exited

	return nil
}

func (srv *Server) writeConfig(ctx context.Context, cfg *config.Config) error {
	confBytes, err := srv.buildBootstrapConfig(ctx, cfg)
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(srv.wd, configFileName)
	log.Ctx(ctx).Debug().Str("service", "envoy").Str("location", cfgPath).Msg("wrote config file to location")

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

	l := log.Ctx(ctx).With().Str("service", "envoy").Logger()
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

func (srv *Server) envoyReady(ctx context.Context) error {
	u := &url.URL{
		Scheme: "http",
		Host:   "unix",
		Path:   "/ready",
	}
	client := srv.envoyAdminClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status code from ready point : %d", resp.StatusCode)
	}
	return nil
}

func (srv *Server) readiness(ctx context.Context, exited chan struct{}) {
	log.Ctx(ctx).Debug().Msg("envoy: starting readiness check")
	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		select {
		case <-exited:
			return
		case <-ctx.Done():
			// small optimization to bring up envoy as ready
			return
		case <-time.After(time.Second):
			if err := srv.envoyReady(ctx); err != nil {
				health.ReportError(health.EnvoyServer, err)
			} else {
				health.ReportRunning(health.EnvoyServer)
			}
		case <-ticker.C:
			if err := srv.envoyReady(ctx); err != nil {
				health.ReportError(health.EnvoyServer, err)
			} else {
				health.ReportRunning(health.EnvoyServer)
			}
		}
	}
}

func (srv *Server) monitorProcess(ctx context.Context, pid int32) error {
	log.Ctx(ctx).Debug().
		Int32("pid", pid).
		Msg("envoy: start monitoring subprocess")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		exists, err := process.PidExistsWithContext(ctx, pid)
		if err != nil {
			return fmt.Errorf("envoy: error retrieving subprocess information: %w", err)
		} else if !exists {
			return errors.New("envoy: subprocess exited")
		}

		// wait for the next tick
		select {
		case <-ctx.Done():
			return nil
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
