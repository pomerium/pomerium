package main // import "github.com/pomerium/pomerium/cmd/pomerium"

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/internal/https"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/options"
	"github.com/pomerium/pomerium/internal/version"
	pb "github.com/pomerium/pomerium/proto/authenticate"
	"github.com/pomerium/pomerium/proxy"
)

var (
	debugFlag   = flag.Bool("debug", false, "run server in debug mode, changes log output to STDOUT and level to info")
	versionFlag = flag.Bool("version", false, "prints the version")
)

func main() {
	mainOpts, err := optionsFromEnvConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium: settings error")
	}
	flag.Parse()
	if *debugFlag || mainOpts.Debug {
		log.SetDebugMode()
	}
	if *versionFlag {
		fmt.Printf("%s", version.FullVersion())
		os.Exit(0)
	}
	log.Info().Str("version", version.FullVersion()).Str("service-mode", mainOpts.Services).Msg("cmd/pomerium")

	grpcAuth := middleware.NewSharedSecretCred(mainOpts.SharedKey)
	grpcOpts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcAuth.ValidateRequest)}
	grpcServer := grpc.NewServer(grpcOpts...)

	var authenticateService *authenticate.Authenticate
	var authHost string
	if mainOpts.Services == "all" || mainOpts.Services == "authenticate" {
		authOpts, err := authenticate.OptionsFromEnvConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("cmd/pomerium: authenticate settings")
		}
		emailValidator := func(p *authenticate.Authenticate) error {
			p.Validator = options.NewEmailValidator(authOpts.AllowedDomains)
			return nil
		}

		authenticateService, err = authenticate.New(authOpts, emailValidator)
		if err != nil {
			log.Fatal().Err(err).Msg("cmd/pomerium: new authenticate")
		}
		authHost = authOpts.RedirectURL.Host
		pb.RegisterAuthenticatorServer(grpcServer, authenticateService)

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
		defer proxyService.AuthenticateClient.Close()
	}

	topMux := http.NewServeMux()
	if authenticateService != nil {
		// Need to handle ping without host lookup for LB
		topMux.HandleFunc("/ping", func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
			fmt.Fprintf(rw, "OK")
		})
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

	log.Fatal().Err(https.ListenAndServeTLS(httpOpts, topMux, grpcServer)).Msg("cmd/pomerium: https serve failure")

}
