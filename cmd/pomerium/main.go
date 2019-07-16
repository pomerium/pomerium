package main // import "github.com/pomerium/pomerium/cmd/pomerium"

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/metrics"
	"github.com/pomerium/pomerium/internal/middleware"
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
	opt, err := parseOptions(*configFile)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: options")
	}
	log.Info().Str("version", version.FullVersion()).Msg("cmd/pomerium")
	grpcAuth := middleware.NewSharedSecretCred(opt.SharedKey)
	grpcOpts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcAuth.ValidateRequest), grpc.StatsHandler(metrics.NewGRPCServerStatsHandler(opt.Services))}
	grpcServer := grpc.NewServer(grpcOpts...)

	mux := http.NewServeMux()

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
	go viper.WatchConfig()

	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Info().
			Str("file", e.Name).
			Msg("cmd/pomerium: configuration file changed")

		opt = handleConfigUpdate(opt, []config.OptionsUpdater{authz, proxy})
	})
	// defer statements ignored anyway :  https://stackoverflow.com/a/17888654
	// defer proxyService.AuthenticateClient.Close()
	// defer proxyService.AuthorizeClient.Close()

	httpOpts := &httputil.Options{
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

	if opt.MetricsAddr != "" {
		go newPromListener(opt.MetricsAddr)
		metrics.SetBuildInfo(opt.Services)
	}

	if srv, err := startRedirectServer(opt.HTTPRedirectAddr); err != nil {
		log.Debug().Str("cause", err.Error()).Msg("cmd/pomerium: http redirect server not started")
	} else {
		defer srv.Close()
	}

	if err := httputil.ListenAndServeTLS(httpOpts, wrapMiddleware(opt, mux), grpcServer); err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: https server")
	}
}

// startRedirectServer starts a http server that redirect HTTP to HTTPS traffic
func startRedirectServer(addr string) (*http.Server, error) {
	if addr == "" {
		return nil, errors.New("no http redirect addr provided")
	}
	srv := &http.Server{
		Addr:         addr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "close")
			url := fmt.Sprintf("https://%s%s", urlutil.StripPort(r.Host), r.URL.String())
			http.Redirect(w, r, url, http.StatusMovedPermanently)
		}),
	}
	log.Info().Str("Addr", addr).Msg("cmd/pomerium: http redirect server started")
	go func() { log.Error().Err(srv.ListenAndServe()).Msg("cmd/pomerium: http server closed") }()
	return srv, nil
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

func newPromListener(addr string) {
	metrics.RegisterView(metrics.HTTPClientViews)
	metrics.RegisterView(metrics.HTTPServerViews)
	metrics.RegisterView(metrics.GRPCClientViews)
	metrics.RegisterView(metrics.GRPCServerViews)
	metrics.RegisterInfoMetrics()
	metrics.RegisterView(metrics.InfoViews)

	log.Info().Str("MetricsAddr", addr).Msg("cmd/pomerium: starting prometheus endpoint")
	log.Error().Err(metrics.NewPromHTTPListener(addr)).Str("MetricsAddr", addr).Msg("cmd/pomerium: could not start metrics exporter")
}

func wrapMiddleware(o *config.Options, mux http.Handler) http.Handler {
	c := middleware.NewChain()
	c = c.Append(metrics.HTTPMetricsHandler("proxy"))
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

func parseOptions(configFile string) (*config.Options, error) {
	o, err := config.OptionsFromViper(configFile)
	if err != nil {
		return nil, err
	}
	if o.Debug {
		log.SetDebugMode()
	}
	if o.LogLevel != "" {
		log.SetLevel(o.LogLevel)
	}
	metrics.AddPolicyCountCallback(o.Services, func() int64 {
		return int64(len(o.Policies))
	})
	checksumInt, err := strconv.ParseInt(fmt.Sprintf("0x%s", o.Checksum()), 0, 64)
	if err != nil {
		log.Warn().Err(err).Msg("Could not parse config checksum into integer")
	}
	metrics.SetConfigChecksum(o.Services, checksumInt)
	return o, nil
}

func handleConfigUpdate(opt *config.Options, services []config.OptionsUpdater) *config.Options {
	newOpt, err := parseOptions(*configFile)
	if err != nil {
		log.Error().Err(err).Msg("cmd/pomerium: could not reload configuration")
		metrics.SetConfigInfo(opt.Services, false, "")
		return opt
	}
	optChecksum := opt.Checksum()
	newOptChecksum := newOpt.Checksum()

	log.Debug().
		Str("old-checksum", optChecksum).
		Str("new-checksum", newOptChecksum).
		Msg("cmd/pomerium: configuration file changed")

	if newOptChecksum == optChecksum {
		log.Debug().Msg("cmd/pomerium: loaded configuration has not changed")
		return opt
	}

	log.Info().Str("checksum", newOptChecksum).Msg("cmd/pomerium: checksum changed")
	for _, service := range services {
		if err := service.UpdateOptions(*newOpt); err != nil {
			log.Error().Err(err).Msg("cmd/pomerium: could not update options")
			metrics.SetConfigInfo(opt.Services, false, "")
		}
	}
	metrics.AddPolicyCountCallback(newOpt.Services, func() int64 {
		return int64(len(newOpt.Policies))
	})
	metrics.SetConfigInfo(newOpt.Services, true, newOptChecksum)
	return newOpt
}
