package main // import "github.com/pomerium/pomerium/cmd/pomerium"

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/https"
	"github.com/pomerium/pomerium/internal/log"
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

	grpcAuth := middleware.NewSharedSecretCred(opt.SharedKey)
	grpcOpts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcAuth.ValidateRequest)}
	grpcServer := grpc.NewServer(grpcOpts...)

	mux := http.NewServeMux()

	_, err = newAuthenticateService(opt, mux, grpcServer)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: authenticate")
	}

	_, err = newAuthorizeService(opt, grpcServer)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: authorize")
	}

	_, err = newProxyService(opt, mux)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: proxy")
	}
	// defer statements ignored anyway :  https://stackoverflow.com/a/17888654
	// defer proxyService.AuthenticateClient.Close()
	// defer proxyService.AuthorizeClient.Close()

	httpOpts := &https.Options{
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

	if srv, err := startRedirectServer(opt.HTTPRedirectAddr); err != nil {
		log.Debug().Err(err).Msg("cmd/pomerium: http redirect server not started")
	} else {
		defer srv.Close()
	}

	if err := https.ListenAndServeTLS(httpOpts, wrapMiddleware(opt, mux), grpcServer); err != nil {
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

func newAuthenticateService(opt *config.Options, mux *http.ServeMux, rpc *grpc.Server) (*authenticate.Authenticate, error) {
	if opt == nil || !config.IsAuthenticate(opt.Services) {
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

func newAuthorizeService(opt *config.Options, rpc *grpc.Server) (*authorize.Authorize, error) {
	if opt == nil || !config.IsAuthorize(opt.Services) {
		return nil, nil
	}
	service, err := authorize.New(opt)
	if err != nil {
		return nil, err
	}
	pbAuthorize.RegisterAuthorizerServer(rpc, service)
	return service, nil
}

func newProxyService(opt *config.Options, mux *http.ServeMux) (*proxy.Proxy, error) {
	if opt == nil || !config.IsProxy(opt.Services) {
		return nil, nil
	}
	service, err := proxy.New(opt)
	if err != nil {
		return nil, err
	}
	mux.Handle("/", service.Handler())
	return service, nil
}

func wrapMiddleware(o *config.Options, mux *http.ServeMux) http.Handler {
	c := middleware.NewChain()
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
	if o != nil && len(o.Headers) != 0 {
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
	return o, nil
}
