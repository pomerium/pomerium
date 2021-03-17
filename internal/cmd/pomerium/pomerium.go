// Package pomerium houses the main pomerium CLI command.
//
package pomerium

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/config"
	databroker_service "github.com/pomerium/pomerium/databroker"
	"github.com/pomerium/pomerium/internal/autocert"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/envoy"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	registry_pb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/proxy"
)

// Run runs the main pomerium application.
func Run(ctx context.Context, configFile string) error {
	log.Info().Str("version", version.FullVersion()).Msg("cmd/pomerium")

	var src config.Source

	src, err := config.NewFileOrEnvironmentSource(configFile)
	if err != nil {
		return err
	}

	src = databroker.NewConfigSource(src)
	logMgr := config.NewLogManager(src)
	defer logMgr.Close()

	// trigger changes when underlying files are changed
	src = config.NewFileWatcherSource(src)

	src, err = autocert.New(src)
	if err != nil {
		return err
	}

	// override the default http transport so we can use the custom CA in the TLS client config (#1570)
	http.DefaultTransport = config.NewHTTPTransport(src)

	metricsMgr := config.NewMetricsManager(src)
	defer metricsMgr.Close()
	traceMgr := config.NewTraceManager(src)
	defer traceMgr.Close()

	// setup the control plane
	controlPlane, err := controlplane.NewServer(src.GetConfig().Options.Services, metricsMgr)
	if err != nil {
		return fmt.Errorf("error creating control plane: %w", err)
	}
	src.OnConfigChange(func(cfg *config.Config) {
		if err := controlPlane.OnConfigChange(cfg); err != nil {
			log.Error().Err(err).Msg("config change")
		}
	})

	if err = controlPlane.OnConfigChange(src.GetConfig()); err != nil {
		return fmt.Errorf("applying config: %w", err)
	}

	_, grpcPort, _ := net.SplitHostPort(controlPlane.GRPCListener.Addr().String())
	_, httpPort, _ := net.SplitHostPort(controlPlane.HTTPListener.Addr().String())

	log.Info().Str("port", grpcPort).Msg("gRPC server started")
	log.Info().Str("port", httpPort).Msg("HTTP server started")

	// create envoy server
	envoyServer, err := envoy.NewServer(src, grpcPort, httpPort)
	if err != nil {
		return fmt.Errorf("error creating envoy server: %w", err)
	}
	defer envoyServer.Close()

	// add services
	if err := setupAuthenticate(src, controlPlane); err != nil {
		return err
	}
	var authorizeServer *authorize.Authorize
	if config.IsAuthorize(src.GetConfig().Options.Services) {
		authorizeServer, err = setupAuthorize(src, controlPlane)
		if err != nil {
			return err
		}
	}
	var dataBrokerServer *databroker_service.DataBroker
	if config.IsDataBroker(src.GetConfig().Options.Services) {
		dataBrokerServer, err = setupDataBroker(src, controlPlane)
		if err != nil {
			return fmt.Errorf("setting up databroker: %w", err)
		}

		if err = setupRegistryServer(src, controlPlane); err != nil {
			return fmt.Errorf("setting up registry: %w", err)
		}
	}

	if err = setupRegistryReporter(src); err != nil {
		return fmt.Errorf("setting up registry reporter: %w", err)
	}
	if err := setupProxy(src, controlPlane); err != nil {
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
		// in non-all-in-one mode we will wait for the initial sync to complete before starting
		// the control plane
		if dataBrokerServer == nil {
			if err := authorizeServer.WaitForInitialSync(ctx); err != nil {
				return err
			}
		}
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

func setupAuthenticate(src config.Source, controlPlane *controlplane.Server) error {
	if !config.IsAuthenticate(src.GetConfig().Options.Services) {
		return nil
	}

	svc, err := authenticate.New(src.GetConfig())
	if err != nil {
		return fmt.Errorf("error creating authenticate service: %w", err)
	}

	authenticateURL, err := src.GetConfig().Options.GetAuthenticateURL()
	if err != nil {
		return fmt.Errorf("error getting authenticate URL: %w", err)
	}

	src.OnConfigChange(svc.OnConfigChange)
	svc.OnConfigChange(src.GetConfig())
	host := urlutil.StripPort(authenticateURL.Host)
	sr := controlPlane.HTTPRouter.Host(host).Subrouter()
	svc.Mount(sr)
	log.Info().Str("host", host).Msg("enabled authenticate service")

	return nil
}

func setupAuthorize(src config.Source, controlPlane *controlplane.Server) (*authorize.Authorize, error) {
	svc, err := authorize.New(src.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("error creating authorize service: %w", err)
	}
	envoy_service_auth_v3.RegisterAuthorizationServer(controlPlane.GRPCServer, svc)

	log.Info().Msg("enabled authorize service")
	src.OnConfigChange(svc.OnConfigChange)
	svc.OnConfigChange(src.GetConfig())
	return svc, nil
}

func setupDataBroker(src config.Source, controlPlane *controlplane.Server) (*databroker_service.DataBroker, error) {
	svc, err := databroker_service.New(src.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("error creating databroker service: %w", err)
	}
	svc.Register(controlPlane.GRPCServer)
	log.Info().Msg("enabled databroker service")
	src.OnConfigChange(svc.OnConfigChange)
	svc.OnConfigChange(src.GetConfig())
	return svc, nil
}

func setupRegistryServer(src config.Source, controlPlane *controlplane.Server) error {
	svc := registry.NewInMemoryServer(context.TODO(), registryTTL)
	registry_pb.RegisterRegistryServer(controlPlane.GRPCServer, svc)
	log.Info().Msg("enabled service discovery")
	return nil
}

func setupRegistryReporter(src config.Source) error {
	reporter := new(registry.Reporter)
	src.OnConfigChange(reporter.OnConfigChange)
	reporter.OnConfigChange(src.GetConfig())
	return nil
}

func setupProxy(src config.Source, controlPlane *controlplane.Server) error {
	if !config.IsProxy(src.GetConfig().Options.Services) {
		return nil
	}

	svc, err := proxy.New(src.GetConfig())
	if err != nil {
		return fmt.Errorf("error creating proxy service: %w", err)
	}
	controlPlane.HTTPRouter.PathPrefix("/").Handler(svc)

	log.Info().Msg("enabled proxy service")
	src.OnConfigChange(svc.OnConfigChange)
	svc.OnConfigChange(src.GetConfig())

	return nil
}
