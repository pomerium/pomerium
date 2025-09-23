package reconciler

/*
 * This is a main control loop for the reconciler service.
 *
 */

import (
	"context"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
)

type service struct {
	config *reconcilerConfig

	databrokerRateLimit *rate.Limiter

	bundles BundleQueue

	fullSyncRequest        chan struct{}
	bundleSyncRequest      chan struct{}
	periodicUpdateInterval atomic.Pointer[time.Duration]
}

// Run creates a new bundle updater client
// that runs until the context is canceled or a fatal error occurs.
func Run(ctx context.Context, opts ...Option) error {
	config := newConfig(opts...)

	c := &service{
		config:              config,
		databrokerRateLimit: rate.NewLimiter(rate.Limit(config.databrokerRPS), 1),
		fullSyncRequest:     make(chan struct{}, 1),
	}
	c.periodicUpdateInterval.Store(&config.checkForUpdateIntervalWhenDisconnected)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return c.watchUpdates(ctx) })
	eg.Go(func() error { return c.SyncLoop(ctx) })

	return eg.Wait()
}

func (c *service) watchUpdates(ctx context.Context) error {
	return c.config.api.Watch(ctx,
		connect_mux.WithOnConnected(func(_ context.Context) {
			c.triggerFullUpdate(true)
		}),
		connect_mux.WithOnDisconnected(func(_ context.Context) {
			c.triggerFullUpdate(false)
		}),
		connect_mux.WithOnBundleUpdated(func(_ context.Context, key string) {
			c.triggerBundleUpdate(key)
		}),
	)
}

func (c *service) triggerBundleUpdate(id string) {
	c.periodicUpdateInterval.Store(&c.config.checkForUpdateIntervalWhenConnected)
	c.bundles.MarkForSync(id)

	select {
	case c.fullSyncRequest <- struct{}{}:
	default:
	}
}

func (c *service) triggerFullUpdate(connected bool) {
	timeout := c.config.checkForUpdateIntervalWhenDisconnected
	if connected {
		timeout = c.config.checkForUpdateIntervalWhenConnected
	}
	c.periodicUpdateInterval.Store(&timeout)

	select {
	case c.fullSyncRequest <- struct{}{}:
	default:
	}
}
