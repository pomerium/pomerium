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

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.FullVersion())
		os.Exit(0)
	}
	opt, err := parseOptions()
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: options")
	}

	grpcAuth := middleware.NewSharedSecretCred(opt.SharedKey)
	grpcOpts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcAuth.ValidateRequest)}
	grpcServer := grpc.NewServer(grpcOpts...)

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		fmt.Fprintf(rw, version.UserAgent())
	})

	_, err = newAuthenticateService(opt.Services, mux, grpcServer)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: authenticate")
	}

	_, err = newAuthorizeService(opt.Services, grpcServer)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: authorize")
	}

	_, err = newProxyService(opt.Services, mux)
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
	if err := https.ListenAndServeTLS(httpOpts, mux, grpcServer); err != nil {
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

func newAuthenticateService(s string, mux *http.ServeMux, rpc *grpc.Server) (*authenticate.Authenticate, error) {
	if !isAuthenticate(s) {
		return nil, nil
	}
	opts, err := authenticate.OptionsFromEnvConfig()
	if err != nil {
		return nil, err
	}
	service, err := authenticate.New(opts)
	if err != nil {
		return nil, err
	}
	pbAuthenticate.RegisterAuthenticatorServer(rpc, service)
	mux.Handle(urlutil.StripPort(opts.AuthenticateURL.Host)+"/", service.Handler())
	return service, nil
}

func newAuthorizeService(s string, rpc *grpc.Server) (*authorize.Authorize, error) {
	if !isAuthorize(s) {
		return nil, nil
	}
	opts, err := authorize.OptionsFromEnvConfig()
	if err != nil {
		return nil, err
	}
	service, err := authorize.New(opts)
	if err != nil {
		return nil, err
	}
	pbAuthorize.RegisterAuthorizerServer(rpc, service)
	return service, nil
}

func newProxyService(s string, mux *http.ServeMux) (*proxy.Proxy, error) {
	if !isProxy(s) {
		return nil, nil
	}
	opts, err := proxy.OptionsFromEnvConfig()
	if err != nil {
		return nil, err
	}
	service, err := proxy.New(opts)
	if err != nil {
		return nil, err
	}
	mux.Handle("/", service.Handler())
	return service, nil
}

func parseOptions() (*Options, error) {
	o, err := optionsFromEnvConfig()
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
