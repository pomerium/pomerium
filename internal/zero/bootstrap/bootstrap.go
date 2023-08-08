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
	"crypto/cipher"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"


	"github.com/pomerium/pomerium/config"
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
func (svc *BootstrapConfigSource) Run(ctx context.Context) error {
	svc.tryLoadInitial(ctx)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return svc.watchUpdates(ctx) })
	eg.Go(func() error { return svc.updateLoop(ctx) })

	return eg.Wait()
}

func (svc *BootstrapConfigSource) watchUpdates(ctx context.Context) error {
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

func (svc *BootstrapConfigSource) updateLoop(ctx context.Context) error {
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

		err := svc.update(ctx)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("failed to update bootstrap config")
		}
	}
}

// triggerUpdate triggers an update of the bootstrap config
// and sets the interval for the next update
func (svc *BootstrapConfigSource) triggerUpdate(newUpdateInterval time.Duration) {
	svc.updateInterval.Store(newUpdateInterval)

	select {
	case svc.checkForUpdate <- struct{}{}:
	default:
	}
}

func (svc *BootstrapConfigSource) update(ctx context.Context) error {
	current := svc.GetConfig()
	cfg := current.Clone()

	err := tryUpdateAndSave(ctx, cfg.Options, svc.clusterAPI, svc.fileCachePath, svc.fileCipher)
	if err != nil {
		return err
	}

	_ = svc.SetConfig(ctx, cfg)

	return nil
}

func tryUpdateAndSave(
	ctx context.Context,
	dst *config.Options,
	clusterAPI cluster_api.ClientWithResponsesInterface,
	fileCachePath string,
	fileCipher cipher.AEAD,
) error {
	err := LoadBootstrapConfigFromAPI(ctx, dst, clusterAPI)
	if err != nil {
		return fmt.Errorf("load bootstrap config from API: %w", err)
	}

	err = SaveBootstrapConfigToFile(dst, fileCachePath, fileCipher)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Msg("failed to save bootstrap config to file, note it may prevent Pomerium from starting up in case of connectivity issues")
	}

	return nil
}

func (src *BootstrapConfigSource) tryLoadInitial(ctx context.Context) {
	dst := src.GetConfig()

	err := tryUpdateAndSave(ctx, dst.Options, src.clusterAPI, src.fileCachePath, src.fileCipher)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to load bootstrap config")
		src.tryLoadFromFile(ctx)
		return
	}

	src.SetConfig(ctx, dst)
}

func (src *BootstrapConfigSource) tryLoadFromFile(ctx context.Context) {
	dst := src.GetConfig()

	err := LoadBootstrapConfigFromFile(dst.Options, src.fileCachePath, src.fileCipher)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to load bootstrap config from file")
		return
	}

	src.SetConfig(ctx, dst)
}
