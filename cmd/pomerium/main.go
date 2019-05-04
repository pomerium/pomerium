package main // import "github.com/pomerium/pomerium/cmd/pomerium"

import (
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

var (
	debugFlag   = flag.Bool("debug", false, "run server in debug mode, changes log output to STDOUT and level to info")
	versionFlag = flag.Bool("version", false, "prints the version")
)

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Printf("%s\n", version.FullVersion())
		os.Exit(0)
	}
	mainOpts, err := optionsFromEnvConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: settings error")
	}
	if *debugFlag || mainOpts.Debug {
		log.SetDebugMode()
	}
	if mainOpts.LogLevel != "" {
		log.SetLevel(mainOpts.LogLevel)
	}
	log.Info().Str("version", version.FullVersion()).Str("user-agent", version.UserAgent()).Str("service", mainOpts.Services).Msg("cmd/pomerium")

	grpcAuth := middleware.NewSharedSecretCred(mainOpts.SharedKey)
	grpcOpts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcAuth.ValidateRequest)}
	grpcServer := grpc.NewServer(grpcOpts...)

	var authenticateService *authenticate.Authenticate
	var authHost string
	if mainOpts.Services == "all" || mainOpts.Services == "authenticate" {
		opts, err := authenticate.OptionsFromEnvConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("cmd/pomerium: authenticate settings")
		}
		authenticateService, err = authenticate.New(opts)
		if err != nil {
			log.Fatal().Err(err).Msg("cmd/pomerium: new authenticate")
		}
		authHost = urlutil.StripPort(opts.AuthenticateURL.Host)
		pbAuthenticate.RegisterAuthenticatorServer(grpcServer, authenticateService)
	}

	var authorizeService *authorize.Authorize
	if mainOpts.Services == "all" || mainOpts.Services == "authorize" {
		opts, err := authorize.OptionsFromEnvConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("cmd/pomerium: authorize settings")
		}
		authorizeService, err = authorize.New(opts)
		if err != nil {
			log.Fatal().Err(err).Msg("cmd/pomerium: new authorize")
		}
		pbAuthorize.RegisterAuthorizerServer(grpcServer, authorizeService)
	}

	var proxyService *proxy.Proxy
	if mainOpts.Services == "all" || mainOpts.Services == "proxy" {
		proxyOpts, err := proxy.OptionsFromEnvConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("cmd/pomerium: proxy settings")
		}

		proxyService, err = proxy.New(proxyOpts)
		if err != nil {
			log.Fatal().Err(err).Msg("cmd/pomerium: new proxy")
		}
		// cleanup our RPC services
		defer proxyService.AuthenticateClient.Close()
		defer proxyService.AuthorizeClient.Close()

	}

	topMux := http.NewServeMux()
	topMux.HandleFunc("/ping", func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		fmt.Fprintf(rw, "OK")
	})
	if authenticateService != nil {
		topMux.Handle(authHost+"/", authenticateService.Handler())
	}
	if proxyService != nil {
		topMux.Handle("/", proxyService.Handler())
	}

	httpOpts := &https.Options{
		Addr:     mainOpts.Addr,
		Cert:     mainOpts.Cert,
		Key:      mainOpts.Key,
		CertFile: mainOpts.CertFile,
		KeyFile:  mainOpts.KeyFile,
	}

	// redirect http to https
	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "close")
			url := fmt.Sprintf("https://%s%s", r.Host, r.URL.String())
			http.Redirect(w, r, url, http.StatusMovedPermanently)
		}),
	}
	go func() { log.Fatal().Err(srv.ListenAndServe()).Msg("cmd/pomerium: http server") }()

	log.Fatal().Err(https.ListenAndServeTLS(httpOpts, topMux, grpcServer)).Msg("cmd/pomerium: https server")

}
