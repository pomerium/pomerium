// Package cmd implements the pomerium zero command.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	}

	return controller.Run(withInterrupt(ctx), opts...)
}

// IsManagedMode returns true if Pomerium should start in managed mode using this command.
func IsManagedMode(configFile string) bool {
	return getToken(configFile) != ""
}

func withInterrupt(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	go func(ctx context.Context) {
		ch := make(chan os.Signal, 2)
		defer signal.Stop(ch)

		signal.Notify(ch, os.Interrupt)
		signal.Notify(ch, syscall.SIGTERM)

		select {
		case sig := <-ch:
			log.Ctx(ctx).Info().Str("signal", sig.String()).Msg("quitting...")
		case <-ctx.Done():
		}
		cancel()
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

func getBootstrapConfigFileName() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(cacheDir, "pomerium")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("error creating cache directory: %w", err)
	}

	return filepath.Join(dir, "bootstrap.dat"), nil
}
