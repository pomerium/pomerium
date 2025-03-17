// Package main contains pomerium
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/version"
	_ "github.com/pomerium/pomerium/internal/zero/bootstrap/writers/filesystem"
	_ "github.com/pomerium/pomerium/internal/zero/bootstrap/writers/k8s"
	zero_cmd "github.com/pomerium/pomerium/internal/zero/cmd"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/envoy/files"
)

func main() {
	convertOldStyleFlags()
	var configFile string
	root := &cobra.Command{
		Use:          "pomerium",
		Version:      fmt.Sprintf("pomerium: %s\nenvoy: %s", version.FullVersion(), files.FullVersion()),
		SilenceUsage: true,
	}
	root.AddCommand(zero_cmd.BuildRootCmd())
	root.PersistentFlags().StringVar(&configFile, "config", "", "Specify configuration file location")
	log.SetLevel(zerolog.InfoLevel)
	ctx := trace.NewContext(context.Background(), trace.NewSyncClient(nil))
	defer func() {
		if err := trace.ShutdownContext(ctx); err != nil {
			log.Error().Err(err).Send()
		}
	}()
	runFn := run
	if zero_cmd.IsManagedMode(configFile) {
		runFn = zero_cmd.Run
	}
	root.RunE = func(_ *cobra.Command, _ []string) error {
		defer log.Ctx(ctx).Info().Msg("cmd/pomerium: exiting")
		return runFn(ctx, configFile)
	}

	if err := root.ExecuteContext(ctx); err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium")
	}
}

func run(ctx context.Context, configFile string) error {
	// ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
	// 	return c.Str("config_file_source", configFile).Bool("bootstrap", true)
	// })

	var src config.Source

	src, err := config.NewFileOrEnvironmentSource(ctx, configFile, files.FullVersion())
	if err != nil {
		return err
	}

	return pomerium.Run(ctx, src)
}

// Converts the "-config" and "-version" single-dash style flags to the
// equivalent "--config" and "--version" flags compatible with cobra. These
// are the only two flags that existed previously, so we don't need to check
// for any others.
func convertOldStyleFlags() {
	for i, arg := range os.Args {
		var found bool
		if arg == "-config" || strings.HasPrefix(arg, "-config=") {
			found = true
			fmt.Fprintln(os.Stderr, "Warning: syntax '-config' is deprecated, use '--config' instead")
		} else if arg == "-version" {
			found = true
			// don't log a warning here, since it could interfere with tools that
			// parse the -version output
		}
		if found {
			os.Args[i] = "-" + arg
		}
	}
}
