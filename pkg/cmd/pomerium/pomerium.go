// Package pomerium houses the main pomerium CLI command.
package pomerium

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/automaxprocs/maxprocs"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	databroker_service "github.com/pomerium/pomerium/databroker"
	"github.com/pomerium/pomerium/internal/autocert"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/version"
	derivecert_config "github.com/pomerium/pomerium/pkg/derivecert/config"
	"github.com/pomerium/pomerium/pkg/envoy"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	"github.com/pomerium/pomerium/proxy"
)

type RunOptions struct {
	fileMgr *filemgr.Manager
}

type RunOption func(*RunOptions)

func (o *RunOptions) apply(opts ...RunOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithOverrideFileManager(fileMgr *filemgr.Manager) RunOption {
	return func(o *RunOptions) {
		o.fileMgr = fileMgr
	}
}

// Run runs the main pomerium application.
func Run(ctx context.Context, src config.Source, opts ...RunOption) error {
	options := RunOptions{}
	options.apply(opts...)

	_, _ = maxprocs.Set(maxprocs.Logger(func(s string, i ...any) { log.Ctx(ctx).Debug().Msgf(s, i...) }))

	evt := log.Ctx(ctx).Info().
		Str("envoy_version", files.FullVersion()).
		Str("version", version.FullVersion())
	if buildTime := version.BuildTime(); buildTime != "" {
		evt = evt.Str("built", buildTime)
	}
	evt.Msg("cmd/pomerium")

	src, err := config.NewLayeredSource(ctx, src, derivecert_config.NewBuilder())
	if err != nil {
		return err
	}
	src = databroker.NewConfigSource(ctx, src, databroker.EnableConfigValidation(true))
	logMgr := config.NewLogManager(ctx, src)
	defer logMgr.Close()

	// trigger changes when underlying files are changed
	src = config.NewFileWatcherSource(ctx, src)

	src, err = autocert.New(ctx, src)
	if err != nil {
		return err
	}

	// override the default http transport so we can use the custom CA in the TLS client config (#1570)
	http.DefaultTransport = config.NewHTTPTransport(src)

	metricsMgr := config.NewMetricsManager(ctx, src)
	defer metricsMgr.Close()
	traceMgr := config.NewTraceManager(ctx, src)
	defer traceMgr.Close()

	eventsMgr := events.New()

	fileMgr := options.fileMgr
	if fileMgr == nil {
		fileMgr = filemgr.NewManager()
	}

	cfg := src.GetConfig()

	// setup the control plane
	controlPlane, err := controlplane.NewServer(ctx, cfg, metricsMgr, eventsMgr, fileMgr)
	if err != nil {
		return fmt.Errorf("error creating control plane: %w", err)
	}
	src.OnConfigChange(ctx,
		func(ctx context.Context, cfg *config.Config) {
			if err := controlPlane.OnConfigChange(ctx, cfg); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("config change")
			}
		})

	if err = controlPlane.OnConfigChange(ctx, src.GetConfig()); err != nil {
		return fmt.Errorf("applying config: %w", err)
	}

	log.Ctx(ctx).Info().
		Str("grpc-port", src.GetConfig().GRPCPort).
		Str("http-port", src.GetConfig().HTTPPort).
		Str("outbound-port", src.GetConfig().OutboundPort).
		Str("metrics-port", src.GetConfig().MetricsPort).
		Str("debug-port", src.GetConfig().DebugPort).
		Str("acme-tls-alpn-port", src.GetConfig().ACMETLSALPNPort).
		Msg("server started")

	// create envoy server
	envoyServer, err := envoy.NewServer(ctx, src, controlPlane.Builder)
	if err != nil {
		return fmt.Errorf("error creating envoy server: %w", err)
	}
	defer envoyServer.Close()

	// add services
	if err := setupAuthenticate(ctx, src, controlPlane); err != nil {
		return err
	}
	var authorizeServer *authorize.Authorize
	if config.IsAuthorize(src.GetConfig().Options.Services) {
		authorizeServer, err = setupAuthorize(ctx, src, controlPlane)
		if err != nil {
			return err
		}
	}
	var dataBrokerServer *databroker_service.DataBroker
	if config.IsDataBroker(src.GetConfig().Options.Services) {
		dataBrokerServer, err = setupDataBroker(ctx, src, controlPlane, eventsMgr)
		if err != nil {
			return fmt.Errorf("setting up databroker: %w", err)
		}
	}

	if err = setupRegistryReporter(ctx, src); err != nil {
		return fmt.Errorf("setting up registry reporter: %w", err)
	}
	if err := setupProxy(ctx, src, controlPlane); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	go func(ctx context.Context) {
		ch := make(chan os.Signal, 2)
		defer signal.Stop(ch)

		signal.Notify(ch, os.Interrupt)
		signal.Notify(ch, syscall.SIGTERM)

		select {
		case <-ch:
		case <-ctx.Done():
		}
		cancel()
	}(ctx)

	// run everything
	eg, ctx := errgroup.WithContext(ctx)
	if authorizeServer != nil {
		eg.Go(func() error {
			return authorizeServer.Run(ctx)
		})
	}
	eg.Go(func() error {
		return controlPlane.Run(ctx)
	})
	if dataBrokerServer != nil {
		eg.Go(func() error {
			return dataBrokerServer.Run(ctx)
		})
	}
	return eg.Wait()
}

func setupAuthenticate(ctx context.Context, src config.Source, controlPlane *controlplane.Server) error {
	if !config.IsAuthenticate(src.GetConfig().Options.Services) {
		return nil
	}

	svc, err := authenticate.New(ctx, src.GetConfig())
	if err != nil {
		return fmt.Errorf("error creating authenticate service: %w", err)
	}
	err = controlPlane.EnableAuthenticate(ctx, svc)
	if err != nil {
		return fmt.Errorf("error adding authenticate service to control plane: %w", err)
	}

	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())
	log.Ctx(ctx).Info().Msg("enabled authenticate service")

	return nil
}

func setupAuthorize(ctx context.Context, src config.Source, controlPlane *controlplane.Server) (*authorize.Authorize, error) {
	svc, err := authorize.New(ctx, src.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("error creating authorize service: %w", err)
	}
	envoy_service_auth_v3.RegisterAuthorizationServer(controlPlane.GRPCServer, svc)

	log.Ctx(ctx).Info().Msg("enabled authorize service")
	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())
	return svc, nil
}

func setupDataBroker(ctx context.Context,
	src config.Source,
	controlPlane *controlplane.Server,
	eventsMgr *events.Manager,
) (*databroker_service.DataBroker, error) {
	svc, err := databroker_service.New(ctx, src.GetConfig(), eventsMgr)
	if err != nil {
		return nil, fmt.Errorf("error creating databroker service: %w", err)
	}
	svc.Register(controlPlane.GRPCServer)
	log.Ctx(ctx).Info().Msg("enabled databroker service")
	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())
	return svc, nil
}

func setupRegistryReporter(ctx context.Context, src config.Source) error {
	reporter := registry.NewReporter()
	src.OnConfigChange(ctx, reporter.OnConfigChange)
	reporter.OnConfigChange(ctx, src.GetConfig())
	return nil
}

func setupProxy(ctx context.Context, src config.Source, controlPlane *controlplane.Server) error {
	if !config.IsProxy(src.GetConfig().Options.Services) {
		return nil
	}

	svc, err := proxy.New(ctx, src.GetConfig())
	if err != nil {
		return fmt.Errorf("error creating proxy service: %w", err)
	}
	err = controlPlane.EnableProxy(ctx, svc)
	if err != nil {
		return fmt.Errorf("error adding proxy service to control plane: %w", err)
	}

	log.Ctx(ctx).Info().Msg("enabled proxy service")
	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())

	return nil
}
