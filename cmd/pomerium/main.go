package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/envoy/files"
)

var (
	versionFlag = flag.Bool("version", false, "prints the version")
	configFile  = flag.String("config", "", "Specify configuration file location")
)

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Println("pomerium:", version.FullVersion())
		fmt.Println("envoy:", files.FullVersion())
		return
	}

	ctx := context.Background()
	if err := run(ctx); !errors.Is(err, context.Canceled) {
		log.Fatal().Err(err).Msg("cmd/pomerium")
	}
	log.Info(ctx).Msg("cmd/pomerium: exiting")
}

func run(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("config_file_source", *configFile).Bool("bootstrap", true)
	})

	var src config.Source

	src, err := config.NewFileOrEnvironmentSource(*configFile, files.FullVersion())
	if err != nil {
		return err
	}

	return pomerium.Run(ctx, src)
}
