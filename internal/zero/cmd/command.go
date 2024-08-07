// Package cmd implements the pomerium zero command.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/controller"
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

	return controller.Run(withInterrupt(ctx), opts...)
}

// IsManagedMode returns true if Pomerium should start in managed mode using this command.
func IsManagedMode(configFile string) bool {
	return getToken(configFile) != ""
}

func withInterrupt(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancelCause(ctx)
	go func(ctx context.Context) {
		defer cancel(context.Canceled)

		ch := make(chan os.Signal, 2)
		defer signal.Stop(ch)

		signal.Notify(ch, os.Interrupt)
		signal.Notify(ch, syscall.SIGTERM)

		select {
		case sig := <-ch:
			cancel(fmt.Errorf("received signal: %s", sig))
		case <-ctx.Done():
		}
	}(ctx)
	return ctx
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
