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
	cluster_api "github.com/pomerium/zero-sdk/cluster"
	connect_mux "github.com/pomerium/zero-sdk/connect-mux"
)

const (
	// DefaultCheckForUpdateInterval is the default interval to check for updates
	// if there is no connection to the update service
	DefaultCheckForUpdateInterval = 5 * time.Minute
	// DefaultCheckForUpdateIntervalWhenConnected is the default interval to check for updates
	// if there is a connection to the update service
	DefaultCheckForUpdateIntervalWhenConnected = 2 * time.Hour
)

// Run initializes the bootstrap config source
func (svc *Source) Run(
	ctx context.Context,
	clusterAPI cluster_api.ClientWithResponsesInterface,
	mux *connect_mux.Mux,
	fileCachePath string,
) error {
	svc.clusterAPI = clusterAPI
	svc.connectMux = mux
	svc.fileCachePath = fileCachePath

	svc.tryLoadInitial(ctx)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return svc.watchUpdates(ctx) })
	eg.Go(func() error { return svc.updateLoop(ctx) })

	return eg.Wait()
}

func (svc *Source) watchUpdates(ctx context.Context) error {
	return svc.connectMux.Watch(ctx,
		connect_mux.WithOnConnected(func(_ context.Context) {
			svc.triggerUpdate(DefaultCheckForUpdateIntervalWhenConnected)
		}),
		connect_mux.WithOnDisconnected(func(_ context.Context) {
			svc.triggerUpdate(DefaultCheckForUpdateInterval)
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
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-svc.checkForUpdate:
		case <-ticker.C:
		}
		ticker.Reset(svc.updateInterval.Load())

		err := svc.tryUpdateAndSave(ctx)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("failed to update bootstrap config")
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

func (svc *Source) tryUpdateAndSave(ctx context.Context) error {
	cfg, err := LoadBootstrapConfigFromAPI(ctx, svc.clusterAPI)
	if err != nil {
		return fmt.Errorf("load bootstrap config from API: %w", err)
	}

	err = SaveBootstrapConfigToFile(cfg, svc.fileCachePath, svc.fileCipher)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Msg("failed to save bootstrap config to file, note it may prevent Pomerium from starting up in case of connectivity issues")
	}

	svc.UpdateBootstrap(ctx, *cfg)
	return nil
}

func (svc *Source) tryLoadInitial(ctx context.Context) {
	err := svc.tryUpdateAndSave(ctx)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to load bootstrap config")
		svc.tryLoadFromFile(ctx)
		return
	}
}

func (svc *Source) tryLoadFromFile(ctx context.Context) {
	cfg, err := LoadBootstrapConfigFromFile(svc.fileCachePath, svc.fileCipher)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to load bootstrap config from file")
		return
	}

	svc.UpdateBootstrap(ctx, *cfg)
}
