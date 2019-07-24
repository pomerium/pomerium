package main // import "github.com/pomerium/pomerium/cmd/pomerium"

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	pbAuthenticate "github.com/pomerium/pomerium/proto/authenticate"
	pbAuthorize "github.com/pomerium/pomerium/proto/authorize"
	"github.com/pomerium/pomerium/proxy"
)

var versionFlag = flag.Bool("version", false, "prints the version")
var configFile = flag.String("config", "", "Specify configuration file location")

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.FullVersion())
		os.Exit(0)
	}
	opt, err := config.ParseOptions(*configFile)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: options")
	}
	log.Info().Str("version", version.FullVersion()).Msg("cmd/pomerium")

	setupMetrics(opt)
	setupTracing(opt)
	setupHTTPRedirectServer(opt)

	mux := http.NewServeMux()
	grpcServer := setupGRPCServer(opt)
	_, err = newAuthenticateService(*opt, mux, grpcServer)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: authenticate")
	}

	authz, err := newAuthorizeService(*opt, grpcServer)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: authorize")
	}

	proxy, err := newProxyService(*opt, mux)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: proxy")
	}
	defer proxy.AuthenticateClient.Close()
	defer proxy.AuthorizeClient.Close()

	go viper.WatchConfig()

	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("cmd/pomerium: config file changed")
		opt = config.HandleConfigUpdate(*configFile, opt, []config.OptionsUpdater{authz, proxy})
	})

	srv, err := httputil.NewTLSServer(configToServerOptions(opt), mainHandler(opt, mux), grpcServer)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: couldn't start pomerium")
	}
	httputil.Shutdown(srv)

	os.Exit(0)
}

func newAuthenticateService(opt config.Options, mux *http.ServeMux, rpc *grpc.Server) (*authenticate.Authenticate, error) {
	if !config.IsAuthenticate(opt.Services) {
		return nil, nil
	}
	service, err := authenticate.New(opt)
	if err != nil {
		return nil, err
	}
	pbAuthenticate.RegisterAuthenticatorServer(rpc, service)
	mux.Handle(urlutil.StripPort(opt.AuthenticateURL.Host)+"/", service.Handler())
	return service, nil
}

func newAuthorizeService(opt config.Options, rpc *grpc.Server) (*authorize.Authorize, error) {
	if !config.IsAuthorize(opt.Services) {
		return nil, nil
	}
	service, err := authorize.New(opt)
	if err != nil {
		return nil, err
	}
	pbAuthorize.RegisterAuthorizerServer(rpc, service)
	return service, nil
}

func newProxyService(opt config.Options, mux *http.ServeMux) (*proxy.Proxy, error) {
	if !config.IsProxy(opt.Services) {
		return nil, nil
	}
	service, err := proxy.New(opt)
	if err != nil {
		return nil, err
	}
	mux.Handle("/", service.Handler())
	return service, nil
}

func mainHandler(o *config.Options, mux http.Handler) http.Handler {
	c := middleware.NewChain()
	c = c.Append(metrics.HTTPMetricsHandler(o.Services))
	c = c.Append(log.NewHandler(log.Logger))
	c = c.Append(log.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		log.FromRequest(r).Debug().
			Dur("duration", duration).
			Int("size", size).
			Int("status", status).
			Str("email", r.Header.Get(proxy.HeaderEmail)).
			Str("group", r.Header.Get(proxy.HeaderGroups)).
			Str("method", r.Method).
			Str("service", o.Services).
			Str("url", r.URL.String()).
			Msg("http-request")
	}))
	if len(o.Headers) != 0 {
		c = c.Append(middleware.SetHeaders(o.Headers))
	}
	c = c.Append(log.ForwardedAddrHandler("fwd_ip"))
	c = c.Append(log.RemoteAddrHandler("ip"))
	c = c.Append(log.UserAgentHandler("user_agent"))
	c = c.Append(log.RefererHandler("referer"))
	c = c.Append(log.RequestIDHandler("req_id", "Request-Id"))
	c = c.Append(middleware.Healthcheck("/ping", version.UserAgent()))
	return c.Then(mux)
}

func configToServerOptions(opt *config.Options) *httputil.ServerOptions {
	return &httputil.ServerOptions{
		Addr:              opt.Addr,
		Cert:              opt.Cert,
		Key:               opt.Key,
		CertFile:          opt.CertFile,
		KeyFile:           opt.KeyFile,
		ReadTimeout:       opt.ReadTimeout,
		WriteTimeout:      opt.WriteTimeout,
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		IdleTimeout:       opt.IdleTimeout,
	}
}

func setupMetrics(opt *config.Options) {
	if opt.MetricsAddr != "" {
		if handler, err := metrics.PrometheusHandler(); err != nil {
			log.Error().Err(err).Msg("cmd/pomerium: couldn't start metrics server")
		} else {
			serverOpts := &httputil.ServerOptions{Addr: opt.MetricsAddr}
			srv := httputil.NewHTTPServer(serverOpts, handler)
			go httputil.Shutdown(srv)
		}
	}
}

func setupTracing(opt *config.Options) {
	if opt.TracingProvider != "" {
		tracingOpts := &trace.TracingOptions{
			Provider:                opt.TracingProvider,
			Service:                 opt.Services,
			Debug:                   opt.TracingDebug,
			JaegerAgentEndpoint:     opt.TracingJaegerAgentEndpoint,
			JaegerCollectorEndpoint: opt.TracingJaegerCollectorEndpoint,
		}
		if err := trace.RegisterTracing(tracingOpts); err != nil {
			log.Error().Err(err).Msg("cmd/pomerium: couldn't register tracing")
		} else {
			log.Info().Interface("options", tracingOpts).Msg("cmd/pomerium: metrics configured")
		}
	}
}

func setupHTTPRedirectServer(opt *config.Options) {
	if opt.HTTPRedirectAddr != "" {
		serverOpts := httputil.ServerOptions{Addr: opt.HTTPRedirectAddr}
		srv := httputil.NewHTTPServer(&serverOpts, httputil.RedirectHandler())
		go httputil.Shutdown(srv)
	}
}

func setupGRPCServer(opt *config.Options) *grpc.Server {
	grpcAuth := middleware.NewSharedSecretCred(opt.SharedKey)
	grpcOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(grpcAuth.ValidateRequest),
		grpc.StatsHandler(metrics.NewGRPCServerStatsHandler(opt.Services))}
	return grpc.NewServer(grpcOpts...)
}
