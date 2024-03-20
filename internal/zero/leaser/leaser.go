// Package leaser groups all Zero services that should run within a lease.
package leaser

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/retry"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type leaser struct {
	cancel context.CancelCauseFunc
	client databroker.DataBrokerServiceClient
	funcs  []func(ctx context.Context, client databroker.DataBrokerServiceClient) error
}

// GetDataBrokerServiceClient implements the databroker.LeaseHandler interface.
func (c *leaser) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return c.client
}

// RunLeased implements the databroker.LeaseHandler interface.
func (c *leaser) RunLeased(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	for _, fn := range append(c.funcs, databrokerChangeMonitor) {
		fn := fn
		eg.Go(func() error {
			err := fn(ctx, c.client)
			if retry.IsTerminalError(err) {
				c.cancel(err)
			}
			return err
		})
	}
	return eg.Wait()
}

func runWithLease(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	funcs ...func(context.Context, databroker.DataBrokerServiceClient) error,
) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)

	srv := &leaser{
		cancel: cancel,
		client: client,
		funcs:  funcs,
	}
	leaser := databroker.NewLeaser("zero-ctrl", time.Second*30, srv)
	return leaser.Run(ctx)
}
