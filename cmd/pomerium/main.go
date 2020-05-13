package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/cache"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/envoy"
	pbCache "github.com/pomerium/pomerium/internal/grpc/cache"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/proxy"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"golang.org/x/sync/errgroup"
)

var versionFlag = flag.Bool("version", false, "prints the version")
var configFile = flag.String("config", "", "Specify configuration file location")

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium")
	}
}

func run(ctx context.Context) error {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.FullVersion())
		return nil
	}
	opt, err := config.NewOptionsFromConfig(*configFile)
	if err != nil {
		return err
	}
	var optionsUpdaters []config.OptionsUpdater

	log.Info().Str("version", version.FullVersion()).Msg("cmd/pomerium")

	if err := setupMetrics(opt); err != nil {
		return err
	}
	if err := setupTracing(opt); err != nil {
		return err
	}

	// setup the control plane
	controlPlane, err := controlplane.NewServer()
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

	// create envoy server
	envoyServer, err := envoy.NewServer(grpcPort, httpPort)
	if err != nil {
		return fmt.Errorf("error creating envoy server")
	}

	// add services
	if err := setupAuthenticate(opt, controlPlane); err != nil {
		return err
	}
	if err := setupAuthorize(opt, controlPlane, &optionsUpdaters); err != nil {
		return err
	}
	if err := setupCache(opt, controlPlane); err != nil {
		return err
	}
	if err := setupProxy(opt, controlPlane); err != nil {
		return err
	}

	// start the config change listener
	go config.WatchChanges(*configFile, opt, optionsUpdaters)

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, os.Interrupt)
		signal.Notify(ch, syscall.SIGTERM)
		<-ch
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
	host := urlutil.StripPort(opt.AuthenticateURL.Host)
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

func setupCache(opt *config.Options, controlPlane *controlplane.Server) error {
	if !config.IsCache(opt.Services) {
		return nil
	}

	svc, err := cache.New(*opt)
	if err != nil {
		return fmt.Errorf("error creating config service: %w", err)
	}
	defer svc.Close()
	pbCache.RegisterCacheServer(controlPlane.GRPCServer, svc)
	log.Info().Msg("enabled cache service")
	return nil
}

func setupMetrics(opt *config.Options) error {
	if opt.MetricsAddr != "" {
		handler, err := metrics.PrometheusHandler()
		if err != nil {
			return err
		}
		metrics.SetBuildInfo(opt.Services)
		metrics.RegisterInfoMetrics()
		serverOpts := &httputil.ServerOptions{
			Addr:     opt.MetricsAddr,
			Insecure: true,
			Service:  "metrics",
		}
		var wg sync.WaitGroup
		_, err = httputil.NewServer(serverOpts, handler, &wg)
		if err != nil {
			return err
		}
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

func setupTracing(opt *config.Options) error {
	if opt.TracingProvider != "" {
		tracingOpts := &trace.TracingOptions{
			Provider:                opt.TracingProvider,
			Service:                 opt.Services,
			Debug:                   opt.TracingDebug,
			JaegerAgentEndpoint:     opt.TracingJaegerAgentEndpoint,
			JaegerCollectorEndpoint: opt.TracingJaegerCollectorEndpoint,
		}
		if err := trace.RegisterTracing(tracingOpts); err != nil {
			return err
		}
	}
	return nil
}
