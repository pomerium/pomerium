package main

import (
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/cache"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/frontend"
	pgrpc "github.com/pomerium/pomerium/internal/grpc"
	pbAuthorize "github.com/pomerium/pomerium/internal/grpc/authorize"
	pbCache "github.com/pomerium/pomerium/internal/grpc/cache"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/proxy"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

var versionFlag = flag.Bool("version", false, "prints the version")
var configFile = flag.String("config", "", "Specify configuration file location")

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium")
	}
}

func run() error {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.FullVersion())
		return nil
	}
	opt, err := config.NewOptionsFromConfig(*configFile)
	if err != nil {
		return err
	}
	log.Info().Str("version", version.FullVersion()).Msg("cmd/pomerium")
	// since we can have multiple listeners, we create a wait group
	var wg sync.WaitGroup
	if err := setupMetrics(opt, &wg); err != nil {
		return err
	}
	if err := setupTracing(opt); err != nil {
		return err
	}
	if err := setupHTTPRedirectServer(opt, &wg); err != nil {
		return err
	}

	r := newGlobalRouter(opt)
	_, err = newAuthenticateService(*opt, r)
	if err != nil {
		return err
	}
	authz, err := newAuthorizeService(*opt)
	if err != nil {
		return err
	}

	cacheSvc, err := newCacheService(*opt)
	if err != nil {
		return err
	}
	if cacheSvc != nil {
		defer cacheSvc.Close()
	}

	proxy, err := newProxyService(*opt, r)
	if err != nil {
		return err
	}
	if proxy != nil {
		defer proxy.AuthorizeClient.Close()
	}

	opt.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("cmd/pomerium: config file changed")
		opt = config.HandleConfigUpdate(*configFile, opt, []config.OptionsUpdater{authz, proxy})
	})

	if err := newGRPCServer(*opt, authz, cacheSvc, &wg); err != nil {
		return err
	}

	srv, err := httputil.NewServer(httpServerOptions(opt), r, &wg)
	if err != nil {
		return err
	}
	go httputil.Shutdown(srv)
	// Blocks and waits until ALL WaitGroup members have signaled completion
	wg.Wait()
	return nil
}

func newAuthenticateService(opt config.Options, r *mux.Router) (*authenticate.Authenticate, error) {
	if !config.IsAuthenticate(opt.Services) {
		return nil, nil
	}
	service, err := authenticate.New(opt)
	if err != nil {
		return nil, err
	}
	sr := r.Host(urlutil.StripPort(opt.AuthenticateURL.Host)).Subrouter()
	sr.PathPrefix("/").Handler(service.Handler())

	return service, nil
}

func newAuthorizeService(opt config.Options) (*authorize.Authorize, error) {
	if !config.IsAuthorize(opt.Services) {
		return nil, nil
	}
	return authorize.New(opt)
}

func newCacheService(opt config.Options) (*cache.Cache, error) {
	if !config.IsCache(opt.Services) {
		return nil, nil
	}
	return cache.New(opt)
}

func newGRPCServer(opt config.Options, as *authorize.Authorize, cs *cache.Cache, wg *sync.WaitGroup) error {
	if as == nil && cs == nil {
		return nil
	}
	regFn := func(s *grpc.Server) {
		if as != nil {
			pbAuthorize.RegisterAuthorizerServer(s, as)
		}
		if cs != nil {
			pbCache.RegisterCacheServer(s, cs)
		}
	}
	so := &pgrpc.ServerOptions{
		Addr:        opt.GRPCAddr,
		ServiceName: opt.Services,
		KeepaliveParams: keepalive.ServerParameters{
			MaxConnectionAge:      opt.GRPCServerMaxConnectionAge,
			MaxConnectionAgeGrace: opt.GRPCServerMaxConnectionAgeGrace,
		},
		InsecureServer: opt.GRPCInsecure,
	}
	if !opt.GRPCInsecure {
		so.TLSCertificate = opt.TLSConfig.Certificates
	}
	grpcSrv, err := pgrpc.NewServer(so, regFn, wg)
	if err != nil {
		return err
	}
	go pgrpc.Shutdown(grpcSrv)
	return nil
}

func newProxyService(opt config.Options, r *mux.Router) (*proxy.Proxy, error) {
	if !config.IsProxy(opt.Services) {
		return nil, nil
	}
	service, err := proxy.New(opt)
	if err != nil {
		return nil, err
	}
	r.PathPrefix("/").Handler(service)
	return service, nil
}

func newGlobalRouter(o *config.Options) *mux.Router {
	mux := httputil.NewRouter()
	mux.SkipClean(true)
	mux.Use(metrics.HTTPMetricsHandler(o.Services))
	mux.Use(log.NewHandler(log.Logger))
	mux.Use(log.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		log.FromRequest(r).Debug().
			Dur("duration", duration).
			Int("size", size).
			Int("status", status).
			Str("method", r.Method).
			Str("service", o.Services).
			Str("host", r.Host).
			Str("path", r.URL.String()).
			Msg("http-request")
	}))
	if len(o.Headers) != 0 {
		mux.Use(middleware.SetHeaders(o.Headers))
	}
	mux.Use(log.HeadersHandler(httputil.HeadersXForwarded))
	mux.Use(log.RemoteAddrHandler("ip"))
	mux.Use(log.UserAgentHandler("user_agent"))
	mux.Use(log.RefererHandler("referer"))
	mux.Use(log.RequestIDHandler("req_id", "Request-Id"))
	mux.Use(middleware.Healthcheck("/ping", version.UserAgent()))
	mux.HandleFunc("/healthz", httputil.HealthCheck)
	mux.HandleFunc("/ping", httputil.HealthCheck)
	mux.PathPrefix("/.pomerium/assets/").Handler(http.StripPrefix("/.pomerium/assets/", frontend.MustAssetHandler()))

	return mux
}

func setupMetrics(opt *config.Options, wg *sync.WaitGroup) error {
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
		srv, err := httputil.NewServer(serverOpts, handler, wg)
		if err != nil {
			return err
		}
		go httputil.Shutdown(srv)
	}
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

func setupHTTPRedirectServer(opt *config.Options, wg *sync.WaitGroup) error {
	if opt.HTTPRedirectAddr != "" {
		serverOpts := httputil.ServerOptions{
			Addr:              opt.HTTPRedirectAddr,
			Insecure:          true,
			Service:           "HTTP->HTTPS Redirect",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       5 * time.Second,
		}
		h := httputil.RedirectHandler()
		if opt.AutoCert {
			h = opt.AutoCertHandler(h)
		}
		srv, err := httputil.NewServer(&serverOpts, h, wg)
		if err != nil {
			return err
		}
		go httputil.Shutdown(srv)
	}
	return nil
}

func httpServerOptions(opt *config.Options) *httputil.ServerOptions {
	return &httputil.ServerOptions{
		Addr:              opt.Addr,
		TLSConfig:         opt.TLSConfig,
		Insecure:          opt.InsecureServer,
		ReadTimeout:       opt.ReadTimeout,
		WriteTimeout:      opt.WriteTimeout,
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		IdleTimeout:       opt.IdleTimeout,
		Service:           opt.Services,
	}
}
