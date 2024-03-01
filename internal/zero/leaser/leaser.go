// Package leaser groups all Zero services that should run within a lease.
package leaser

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type service struct {
	client databroker.DataBrokerServiceClient
	funcs  []func(ctx context.Context) error
}

// GetDataBrokerServiceClient implements the databroker.LeaseHandler interface.
func (c *service) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return c.client
}

// RunLeased implements the databroker.LeaseHandler interface.
func (c *service) RunLeased(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	for _, fn := range append(c.funcs, c.databrokerChangeMonitor) {
		fn := fn
		eg.Go(func() error {
			return fn(ctx)
		})
	}
	return eg.Wait()
}

// Run runs services within a lease
func Run(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	funcs ...func(ctx context.Context) error,
) error {
	srv := &service{
		client: client,
		funcs:  funcs,
	}
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 0
	leaser := databroker.NewLeaser("zero-ctrl", time.Second*30, srv)
	return backoff.Retry(
		func() error { return leaser.Run(ctx) },
		backoff.WithContext(b, ctx),
	)
}
