package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/pomerium/pomerium/internal/cmd/pomerium"
	"github.com/pomerium/pomerium/internal/envoy/files"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
)

var (
	versionFlag = flag.Bool("version", false, "prints the version")
	configFile  = flag.String("config", "", "Specify configuration file location")
)

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Println("pomerium:", version.FullVersion())
		fmt.Println("envoy:", files.EmbeddedEnvoyProvider.Version()+"+"+files.EmbeddedEnvoyProvider.Checksum())
		return
	}

	ctx := context.Background()
	if err := run(ctx); !errors.Is(err, context.Canceled) {
		log.Fatal().Err(err).Msg("cmd/pomerium")
	}
	log.Info(ctx).Msg("cmd/pomerium: exiting")
}

func run(ctx context.Context) error {
	return pomerium.Run(ctx, *configFile, files.EmbeddedEnvoyProvider)
}
