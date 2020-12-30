package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/pomerium/pomerium/internal/cmd/pomerium"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
)

var (
	versionFlag = flag.Bool("version", false, "prints the version")
	configFile  = flag.String("config", "", "Specify configuration file location")
)

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
	return pomerium.Run(ctx, *configFile)
}
