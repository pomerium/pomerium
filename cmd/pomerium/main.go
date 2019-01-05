package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/pomerium/pomerium/internal/https"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/options"
	"github.com/pomerium/pomerium/internal/version"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/proxy"
)

var (
	debugFlag   = flag.Bool("debug", false, "run server in debug mode, changes log output to STDOUT and level to info")
	versionFlag = flag.Bool("version", false, "prints the version")
)

func main() {
	flag.Parse()
	if *debugFlag {
		log.SetDebugMode()
	}
	if *versionFlag {
		fmt.Printf("%s", version.FullVersion())
		os.Exit(0)
	}
	log.Info().Str("version", version.FullVersion()).Str("user-agent", version.UserAgent()).Msg("cmd/pomerium")
	authOpts, err := authenticate.OptionsFromEnvConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium : failed to parse authenticator settings")
	}
	emailValidator := func(p *authenticate.Authenticator) error {
		p.Validator = options.NewEmailValidator(authOpts.AllowedDomains)
		return nil
	}

	authenticator, err := authenticate.NewAuthenticator(authOpts, emailValidator)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium : failed to create authenticator")
	}

	proxyOpts, err := proxy.OptionsFromEnvConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium : failed to parse proxy settings")
	}

	p, err := proxy.NewProxy(proxyOpts)
	if err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium : failed to create proxy")
	}

	topMux := http.NewServeMux()
	topMux.Handle(authOpts.RedirectURL.Host+"/", authenticator.Handler())
	topMux.Handle("/", p.Handler())
	log.Fatal().Err(https.ListenAndServeTLS(nil, topMux))

}
