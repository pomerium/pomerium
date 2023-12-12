package reconciler

/*
 * This is a main control loop for the reconciler service.
 *
 */

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/pomerium/pomerium/internal/atomicutil"
	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type service struct {
	config *reconcilerConfig

	databrokerRateLimit *rate.Limiter

	bundles BundleQueue

	fullSyncRequest        chan struct{}
	bundleSyncRequest      chan struct{}
	periodicUpdateInterval atomicutil.Value[time.Duration]
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
	c.periodicUpdateInterval.Store(config.checkForUpdateIntervalWhenDisconnected)

	return c.runMainLoop(ctx)
}

// RunLeased implements the databroker.LeaseHandler interface
func (c *service) RunLeased(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return c.watchUpdates(ctx) })
	eg.Go(func() error { return c.SyncLoop(ctx) })

	return eg.Wait()
}

// GetDataBrokerServiceClient implements the databroker.LeaseHandler interface.
func (c *service) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return c.config.databrokerClient
}

func (c *service) runMainLoop(ctx context.Context) error {
	leaser := databroker.NewLeaser("zero-reconciler", time.Second*30, c)
	return RunWithRestart(ctx, func(ctx context.Context) error {
		return leaser.Run(ctx)
	}, c.databrokerChangeMonitor)
}

// databrokerChangeMonitor runs infinite sync loop to see if there is any change in databroker
func (c *service) databrokerChangeMonitor(ctx context.Context) error {
	_, recordVersion, serverVersion, err := databroker.InitialSync(ctx, c.GetDataBrokerServiceClient(), &databroker.SyncLatestRequest{
		Type: BundleCacheEntryRecordType,
	})
	if err != nil {
		return fmt.Errorf("error during initial sync: %w", err)
	}

	stream, err := c.GetDataBrokerServiceClient().Sync(ctx, &databroker.SyncRequest{
		Type:          BundleCacheEntryRecordType,
		ServerVersion: serverVersion,
		RecordVersion: recordVersion,
	})
	if err != nil {
		return fmt.Errorf("error calling sync: %w", err)
	}

	for {
		_, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("error receiving record: %w", err)
		}
	}
}

// run is a main control loop.
// it is very simple and sequential download and reconcile.
// it may be later optimized by splitting between download and reconciliation process,
// as we would get more resource bundles beyond the config.
func (c *service) watchUpdates(ctx context.Context) error {
	return c.config.api.Watch(ctx,
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
	c.periodicUpdateInterval.Store(c.config.checkForUpdateIntervalWhenConnected)
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
	c.periodicUpdateInterval.Store(timeout)

	select {
	case c.fullSyncRequest <- struct{}{}:
	default:
	}
}
