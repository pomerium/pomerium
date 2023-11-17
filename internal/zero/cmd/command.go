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

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

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

	bootstrapConfigFileName, err := getBootstrapConfigFileName()
	if err != nil {
		return fmt.Errorf("error getting bootstrap config path: %w", err)
	}

	return controller.Run(
		withInterrupt(ctx),
		controller.WithAPIToken(token),
		controller.WithClusterAPIEndpoint(getClusterAPIEndpoint()),
		controller.WithConnectAPIEndpoint(getConnectAPIEndpoint()),
		controller.WithBootstrapConfigFileName(bootstrapConfigFileName),
	)
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
	if isatty.IsTerminal(os.Stdin.Fd()) {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		log.Logger = zerolog.New(os.Stderr)
	}

	if rawLvl, ok := os.LookupEnv("LOG_LEVEL"); ok {
		lvl, err := zerolog.ParseLevel(rawLvl)
		if err != nil {
			return err
		}
		log.Logger = log.Logger.Level(lvl)
	} else {
		log.Logger = log.Logger.Level(zerolog.InfoLevel)
	}

	// set the default context logger
	zerolog.DefaultContextLogger = &log.Logger
	return nil
}

func getBootstrapConfigFileName() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(cacheDir, "pomerium")
	if err := os.MkdirAll(dir, 0644); err != nil {
		return "", err
	}

	return filepath.Join(dir, "bootstrap.dat"), nil
}
