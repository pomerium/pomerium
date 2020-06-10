// Package pomerium houses the main pomerium CLI command.
//
package pomerium

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/pomerium/pomerium/internal/telemetry"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/cache"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/envoy"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/proxy"
)

// Run runs the main pomerium application.
func Run(ctx context.Context, configFile string) error {
	opt, err := config.NewOptionsFromConfig(configFile)
	if err != nil {
		return err
	}
	var optionsUpdaters []config.OptionsUpdater

	log.Info().Str("version", version.FullVersion()).Msg("cmd/pomerium")

	if err := setupMetrics(ctx, opt); err != nil {
		return err
	}
	if err := setupTracing(ctx, opt); err != nil {
		return err
	}

	// setup the control plane
	controlPlane, err := controlplane.NewServer(opt.Services)
	if err != nil {
		return fmt.Errorf("error creating control plane: %w", err)
	}
	optionsUpdaters = append(optionsUpdaters, controlPlane)
	err = controlPlane.UpdateOptions(*opt)
	if err != nil {
		return fmt.Errorf("error updating control plane options: %w", err)
	}

	_, grpcPort, _ := net.SplitHostPort(controlPlane.GRPCListener.Addr().String())
	_, httpPort, _ := net.SplitHostPort(controlPlane.HTTPListener.Addr().String())

	log.Info().Str("port", grpcPort).Msg("gRPC server started")
	log.Info().Str("port", httpPort).Msg("HTTP server started")

	// create envoy server
	envoyServer, err := envoy.NewServer(opt, grpcPort, httpPort)
	if err != nil {
		return fmt.Errorf("error creating envoy server: %w", err)
	}

	// add services
	if err := setupAuthenticate(opt, controlPlane); err != nil {
		return err
	}
	if err := setupAuthorize(opt, controlPlane, &optionsUpdaters); err != nil {
		return err
	}
	cacheServer, err := setupCache(opt, controlPlane)
	if err != nil {
		return err
	}
	if err := setupProxy(opt, controlPlane); err != nil {
		return err
	}

	// start the config change listener
	go config.WatchChanges(configFile, opt, optionsUpdaters)

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		ch := make(chan os.Signal, 2)
		defer signal.Stop(ch)

		signal.Notify(ch, os.Interrupt)
		signal.Notify(ch, syscall.SIGTERM)

		select {
		case <-ch:
		case <-ctx.Done():
		}
		cancel()
	}()

	// run everything
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return controlPlane.Run(ctx)
	})
	eg.Go(func() error {
		return envoyServer.Run(ctx)
	})
	if cacheServer != nil {
		eg.Go(func() error {
			return cacheServer.Run(ctx)
		})
	}
	return eg.Wait()
}

func setupAuthenticate(opt *config.Options, controlPlane *controlplane.Server) error {
	if !config.IsAuthenticate(opt.Services) {
		return nil
	}

	svc, err := authenticate.New(*opt)
	if err != nil {
		return fmt.Errorf("error creating authenticate service: %w", err)
	}
	host := urlutil.StripPort(opt.GetAuthenticateURL().Host)
	sr := controlPlane.HTTPRouter.Host(host).Subrouter()
	svc.Mount(sr)
	log.Info().Str("host", host).Msg("enabled authenticate service")

	return nil
}

func setupAuthorize(opt *config.Options, controlPlane *controlplane.Server, optionsUpdaters *[]config.OptionsUpdater) error {
	if !config.IsAuthorize(opt.Services) {
		return nil
	}

	svc, err := authorize.New(*opt)
	if err != nil {
		return fmt.Errorf("error creating authorize service: %w", err)
	}
	envoy_service_auth_v2.RegisterAuthorizationServer(controlPlane.GRPCServer, svc)

	log.Info().Msg("enabled authorize service")

	*optionsUpdaters = append(*optionsUpdaters, svc)
	err = svc.UpdateOptions(*opt)
	if err != nil {
		return fmt.Errorf("error updating authorize options: %w", err)
	}
	return nil
}

func setupCache(opt *config.Options, controlPlane *controlplane.Server) (*cache.Cache, error) {
	if !config.IsCache(opt.Services) {
		return nil, nil
	}

	svc, err := cache.New(*opt)
	if err != nil {
		return nil, fmt.Errorf("error creating config service: %w", err)
	}
	svc.Register(controlPlane.GRPCServer)
	log.Info().Msg("enabled cache service")
	return svc, nil
}

func setupMetrics(ctx context.Context, opt *config.Options) error {
	serviceName := telemetry.ServiceName(opt.Services)
	if opt.MetricsAddr != "" {
		handler, err := metrics.PrometheusHandler(config.EnvoyAdminURL)
		if err != nil {
			return err
		}
		metrics.SetBuildInfo(serviceName)
		metrics.RegisterInfoMetrics()
		serverOpts := &httputil.ServerOptions{
			Addr:     opt.MetricsAddr,
			Insecure: true,
			Service:  "metrics",
		}
		var wg sync.WaitGroup
		srv, err := httputil.NewServer(serverOpts, handler, &wg)
		if err != nil {
			return err
		}
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
	}
	return nil
}

func setupProxy(opt *config.Options, controlPlane *controlplane.Server) error {
	if !config.IsProxy(opt.Services) {
		return nil
	}

	svc, err := proxy.New(*opt)
	if err != nil {
		return fmt.Errorf("error creating proxy service: %w", err)
	}
	controlPlane.HTTPRouter.PathPrefix("/").Handler(svc)
	return nil
}

func setupTracing(ctx context.Context, opt *config.Options) error {
	traceOpts, err := config.NewTracingOptions(opt)
	if err != nil {
		return fmt.Errorf("error setting up tracing: %w", err)
	}
	if traceOpts.Enabled() {
		exporter, err := trace.RegisterTracing(traceOpts)
		if err != nil {
			return err
		}
		go func() {
			<-ctx.Done()
			trace.UnregisterTracing(exporter)
		}()
	}
	return nil
}
