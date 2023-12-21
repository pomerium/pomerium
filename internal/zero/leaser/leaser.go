// Package leaser groups all Zero services that should run within a lease.
package leaser

import (
	"context"
	"time"

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
	for _, fn := range c.funcs {
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
	leaser := databroker.NewLeaser("zero-ctrl", time.Second*30, srv)
	return RunWithRestart(ctx, func(ctx context.Context) error {
		return leaser.Run(ctx)
	}, srv.databrokerChangeMonitor)
}
