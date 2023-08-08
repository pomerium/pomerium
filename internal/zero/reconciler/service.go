package reconciler

/*
 * This is a main control loop for the reconciler service.
 *
 */

import (
	"context"
	"net/url"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/log"
	connect_mux "github.com/pomerium/zero-sdk/connect-mux"
)

type service struct {
	config *reconcilerConfig

	databrokerRateLimit *rate.Limiter
	downloadURLCache    map[string]urlEntry

	bundles Bundles

	fullUpdateRequest    chan struct{}
	bundleUpdatedRequest chan struct{}
	updateInterval       atomicutil.Value[time.Duration]
}

type urlEntry struct {
	URL       url.URL
	ExpiresAt time.Time
}

// Run creates a new bundle updater client
// that runs until the context is canceled or a fatal error occurs.
func Run(ctx context.Context, opts ...Option) error {
	config := newConfig(opts...)

	c := &service{
		config:               config,
		databrokerRateLimit:  rate.NewLimiter(rate.Limit(config.databrokerRPS), 1),
		downloadURLCache:     make(map[string]urlEntry),
		fullUpdateRequest:    make(chan struct{}, 1),
		bundleUpdatedRequest: make(chan struct{}, 1),
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return c.watchUpdates(ctx) })
	eg.Go(func() error { return c.updateLoop(ctx) })

	return eg.Wait()
}

func (c *service) updateLoop(ctx context.Context) error {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
		next, ok := c.bundles.GetNextBundleToSync()
		if ok {
			err := c.SyncBundle(ctx, next)
			if err != nil {
				log.Error(ctx).Err(err).Str("bundle", next).Msg("reconciler: failed to sync bundle")
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-c.fullUpdateRequest:
				c.fullUpdate(ctx)
			default:
				continue
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.fullUpdateRequest:
			c.fullUpdate(ctx)
		case <-ticker.C:
			c.fullUpdate(ctx)
		case <-c.bundleUpdatedRequest:
		}

		ticker.Reset(c.updateInterval.Load())
	}
}

func (c *service) fullUpdate(ctx context.Context) {
	err := c.RefreshBundleList(ctx)
	if err != nil {
		log.Error(ctx).Err(err).Msg("reconciler: failed to refresh bundle list")
		return
	}

	err = c.PurgeRecordsNotInList(ctx)
	if err != nil {
		log.Error(ctx).Err(err).Msg("reconciler: failed to purge records not in list")
		return
	}
}

// run is a main control loop.
// it is very simple and sequential download and reconcile.
// it may be later optimized by splitting between download and reconciliation process,
// as we would get more resource bundles beyond the config.
func (c *service) watchUpdates(ctx context.Context) error {
	return c.config.connectMux.Watch(ctx,
		connect_mux.WithOnConnected(func(ctx context.Context) {
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
	c.updateInterval.Store(c.config.checkForUpdateIntervalWhenConnected)
	c.bundles.MarkForSync(id)

	select {
	case c.bundleUpdatedRequest <- struct{}{}:
	default:
	}
}

func (c *service) triggerFullUpdate(connected bool) {
	timeout := c.config.checkForUpdateIntervalWhenDisconnected
	if connected {
		timeout = c.config.checkForUpdateIntervalWhenConnected
	}
	c.updateInterval.Store(timeout)

	select {
	case c.fullUpdateRequest <- struct{}{}:
	default:
	}
}
