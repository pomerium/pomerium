// Package cmd implements the pomerium zero command.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/controller"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// Run runs the pomerium zero command.
func Run(ctx context.Context, configFile string) error {
	err := setupLogger()
	if err != nil {
		return fmt.Errorf("error setting up logger: %w", err)
	}

	token := getToken(configFile)
	if token == "" {
		return errors.New("no token provided")
	}

	opts := []controller.Option{
		controller.WithAPIToken(token),
		controller.WithClusterAPIEndpoint(getClusterAPIEndpoint()),
		controller.WithConnectAPIEndpoint(getConnectAPIEndpoint()),
		controller.WithOTELAPIEndpoint(getOTELAPIEndpoint()),
		controller.WithTracerProvider(trace.NewTracerProvider(ctx, "Zero")),
	}

	bootstrapConfigFileName, err := getBootstrapConfigFileName()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("would not be able to save cluster bootstrap config, that will prevent Pomerium from starting independent from the control plane")
	} else {
		log.Ctx(ctx).Info().Str("file", bootstrapConfigFileName).Msg("cluster bootstrap config path")
		opts = append(opts, controller.WithBootstrapConfigFileName(bootstrapConfigFileName))

		if uri := getBootstrapConfigWritebackURI(); uri != "" {
			log.Ctx(ctx).Debug().Str("uri", uri).Msg("cluster bootstrap config writeback URI")
			opts = append(opts, controller.WithBootstrapConfigWritebackURI(uri))
		}
	}

	return controller.Run(ctx, opts...)
}

// IsManagedMode returns true if Pomerium should start in managed mode using this command.
func IsManagedMode(configFile string) bool {
	return getToken(configFile) != ""
}

func setupLogger() error {
	if rawLvl, ok := os.LookupEnv("LOG_LEVEL"); ok {
		lvl, err := zerolog.ParseLevel(rawLvl)
		if err != nil {
			return err
		}
		log.SetLevel(lvl)
	}

	return nil
}
