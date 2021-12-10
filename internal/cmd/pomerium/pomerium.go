// Package pomerium houses the main pomerium CLI command.
//
package pomerium

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/config"
	databroker_service "github.com/pomerium/pomerium/databroker"
	"github.com/pomerium/pomerium/internal/autocert"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/envoy"
	"github.com/pomerium/pomerium/internal/envoy/files"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/proxy"
)

// Run runs the main pomerium application.
func Run(ctx context.Context, configFile string) error {
	log.Info(ctx).
		Str("envoy_version", files.FullVersion()).
		Str("version", version.FullVersion()).
		Msg("cmd/pomerium")

	var src config.Source

	src, err := config.NewFileOrEnvironmentSource(configFile, files.FullVersion())
	if err != nil {
		return err
	}

	src = databroker.NewConfigSource(ctx, src)
	logMgr := config.NewLogManager(ctx, src)
	defer logMgr.Close()

	// trigger changes when underlying files are changed
	src = config.NewFileWatcherSource(src)

	src, err = autocert.New(src)
	if err != nil {
		return err
	}

	// override the default http transport so we can use the custom CA in the TLS client config (#1570)
	http.DefaultTransport = config.NewHTTPTransport(src)

	metricsMgr := config.NewMetricsManager(ctx, src)
	defer metricsMgr.Close()
	traceMgr := config.NewTraceManager(ctx, src)
	defer traceMgr.Close()

	// setup the control plane
	controlPlane, err := controlplane.NewServer(src.GetConfig(), metricsMgr)
	if err != nil {
		return fmt.Errorf("error creating control plane: %w", err)
	}
	src.OnConfigChange(ctx,
		func(ctx context.Context, cfg *config.Config) {
			if err := controlPlane.OnConfigChange(ctx, cfg); err != nil {
				log.Error(ctx).Err(err).Msg("config change")
			}
		})

	if err = controlPlane.OnConfigChange(log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("config_file_source", configFile).Bool("bootstrap", true)
	}), src.GetConfig()); err != nil {
		return fmt.Errorf("applying config: %w", err)
	}

	log.Info(ctx).
		Str("grpc-port", src.GetConfig().GRPCPort).
		Str("http-port", src.GetConfig().HTTPPort).
		Str("outbound-port", src.GetConfig().OutboundPort).
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
		dataBrokerServer, err = setupDataBroker(ctx, src, controlPlane)
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

	svc, err := authenticate.New(src.GetConfig())
	if err != nil {
		return fmt.Errorf("error creating authenticate service: %w", err)
	}

	authenticateURL, err := src.GetConfig().Options.GetInternalAuthenticateURL()
	if err != nil {
		return fmt.Errorf("error getting authenticate URL: %w", err)
	}

	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())
	host := urlutil.StripPort(authenticateURL.Host)
	sr := controlPlane.HTTPRouter.Host(host).Subrouter()
	svc.Mount(sr)
	log.Info(context.TODO()).Str("host", host).Msg("enabled authenticate service")

	return nil
}

func setupAuthorize(ctx context.Context, src config.Source, controlPlane *controlplane.Server) (*authorize.Authorize, error) {
	svc, err := authorize.New(src.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("error creating authorize service: %w", err)
	}
	envoy_service_auth_v3.RegisterAuthorizationServer(controlPlane.GRPCServer, svc)

	log.Info(context.TODO()).Msg("enabled authorize service")
	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())
	return svc, nil
}

func setupDataBroker(ctx context.Context, src config.Source, controlPlane *controlplane.Server) (*databroker_service.DataBroker, error) {
	svc, err := databroker_service.New(src.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("error creating databroker service: %w", err)
	}
	svc.Register(controlPlane.GRPCServer)
	log.Info(context.TODO()).Msg("enabled databroker service")
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

	svc, err := proxy.New(src.GetConfig())
	if err != nil {
		return fmt.Errorf("error creating proxy service: %w", err)
	}
	controlPlane.HTTPRouter.PathPrefix("/").Handler(svc)

	log.Info(context.TODO()).Msg("enabled proxy service")
	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())

	return nil
}
