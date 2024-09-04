// Package bootstrap fetches the very initial configuration for Pomerium Core to start.
package bootstrap

/*
 * Initial configuration for Pomerium start-up is obtained from the cloud.
 * Some parameters are derived from the cluster token.
 *
 * The expectation is that if the user wishes to survive a cloud outage,
 * it should be sufficient to set up Pomerium to use a durable database (Postgres)
 * and receive cloud configuration once.
 *
 */

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/retry"
	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
)

const (
	// DefaultCheckForUpdateIntervalWhenDisconnected is the default interval to check for updates
	// if there is no connection to the update service
	DefaultCheckForUpdateIntervalWhenDisconnected = 5 * time.Minute
	// DefaultCheckForUpdateIntervalWhenConnected is the default interval to check for updates
	// if there is a connection to the update service
	DefaultCheckForUpdateIntervalWhenConnected = time.Hour
)

// Run initializes the bootstrap config source
func (svc *Source) Run(ctx context.Context) error {
	svc.tryLoadFromFile(ctx)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return svc.watchUpdates(ctx) })
	eg.Go(func() error { return svc.updateLoop(ctx) })

	return eg.Wait()
}

func (svc *Source) watchUpdates(ctx context.Context) error {
	return svc.api.Watch(ctx,
		connect_mux.WithOnConnected(func(_ context.Context) {
			svc.triggerUpdate(DefaultCheckForUpdateIntervalWhenConnected)
		}),
		connect_mux.WithOnDisconnected(func(_ context.Context) {
			svc.updateInterval.Store(DefaultCheckForUpdateIntervalWhenDisconnected)
		}),
		connect_mux.WithOnBootstrapConfigUpdated(func(_ context.Context) {
			svc.triggerUpdate(DefaultCheckForUpdateIntervalWhenConnected)
		}),
	)
}

func (svc *Source) updateLoop(ctx context.Context) error {
	ticker := time.NewTicker(svc.updateInterval.Load())
	defer ticker.Stop()

	for {
		err := retry.Retry(ctx,
			"update bootstrap", svc.updateAndSave,
			retry.WithWatch("bootstrap config updated", svc.checkForUpdate, nil),
		)
		if err != nil {
			return fmt.Errorf("update bootstrap config: %w", err)
		}

		ticker.Reset(svc.updateInterval.Load())

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-svc.checkForUpdate:
		case <-ticker.C:
		}
	}
}

// triggerUpdate triggers an update of the bootstrap config
// and sets the interval for the next update
func (svc *Source) triggerUpdate(newUpdateInterval time.Duration) {
	svc.updateInterval.Store(newUpdateInterval)

	select {
	case svc.checkForUpdate <- struct{}{}:
	default:
	}
}

func (svc *Source) updateAndSave(ctx context.Context) error {
	cfg, err := svc.api.GetClusterBootstrapConfig(ctx)
	if err != nil {
		return fmt.Errorf("load bootstrap config from API: %w", err)
	}

	svc.UpdateBootstrap(ctx, *cfg)

	if svc.writer == nil {
		return nil
	}

	err = SaveBootstrapConfig(ctx, svc.writer, cfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Msg("failed to save bootstrap config to file, note it may prevent Pomerium from starting up in case of connectivity issues")
	}

	return nil
}

func (svc *Source) tryLoadFromFile(ctx context.Context) {
	if svc.fileCachePath == nil {
		return
	}

	cfg, err := LoadBootstrapConfigFromFile(*svc.fileCachePath, svc.fileCipher)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to load bootstrap config from file")
		return
	}

	svc.UpdateBootstrap(ctx, *cfg)
}
