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
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/cenkalti/backoff/v4"
	"github.com/pomerium/pomerium/internal/log"
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

	var restartFn atomic.Pointer[context.CancelFunc]

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return svc.watchUpdates(ctx, &restartFn) })
	eg.Go(func() error { return svc.updateLoop(ctx, &restartFn) })

	return eg.Wait()
}

func (svc *Source) watchUpdates(
	ctx context.Context, restartFn *atomic.Pointer[context.CancelFunc],
) error {
	restart := func() {
		if f := restartFn.Load(); f != nil {
			(*f)()
		}
	}
	return svc.api.Watch(ctx,
		connect_mux.WithOnConnected(func(_ context.Context) {
			svc.updateInterval.Store(DefaultCheckForUpdateIntervalWhenConnected)
			restart()
		}),
		connect_mux.WithOnDisconnected(func(_ context.Context) {
			svc.updateInterval.Store(DefaultCheckForUpdateIntervalWhenDisconnected)
		}),
		connect_mux.WithOnBootstrapConfigUpdated(func(_ context.Context) {
			svc.updateInterval.Store(DefaultCheckForUpdateIntervalWhenConnected)
			restart()
		}),
	)
}

func (svc *Source) updateLoop(
	ctx context.Context, restartFn *atomic.Pointer[context.CancelFunc],
) error {
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, svc.updateInterval.Load())
		restartFn.Store(&cancel)

		e := backoff.NewExponentialBackOff()
		e.MaxInterval = 5 * time.Minute
		e.MaxElapsedTime = 0
		e.Multiplier = 2
		b := backoff.WithContext(e, attemptCtx)

		err := backoff.Retry(func() error { return svc.updateAndSave(attemptCtx) }, b)
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("update bootstrap config: %w", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-attemptCtx.Done():
		}
	}
}

func (svc *Source) updateAndSave(ctx context.Context) error {
	cfg, err := svc.api.GetClusterBootstrapConfig(ctx)
	if err != nil {
		return fmt.Errorf("load bootstrap config from API: %w", err)
	}

	svc.UpdateBootstrap(ctx, *cfg)

	if svc.fileCachePath == nil {
		return nil
	}

	err = SaveBootstrapConfigToFile(cfg, *svc.fileCachePath, svc.fileCipher)
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
