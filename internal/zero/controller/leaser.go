package controller

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/retry"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type leaser struct {
	client databroker.DataBrokerServiceClient
	funcs  []DbcFunc
}

// GetDataBrokerServiceClient implements the databroker.LeaseHandler interface.
func (c *leaser) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return c.client
}

// RunLeased implements the databroker.LeaseHandler interface.
func (c *leaser) RunLeased(ctx context.Context) error {
	log.Debug(ctx).Msg("leaser: running leased functions")

	eg, ctx := errgroup.WithContext(ctx)
	for _, fn := range c.funcs {
		eg.Go(func() error {
			return retry.WithBackoff(ctx, func(ctx context.Context) error { return fn(ctx, c.client) })
		})
	}
	err := eg.Wait()
	log.Debug(ctx).Err(err).Msg("leaser: done running leased functions")
	return err
}

func WithLease(funcs ...DbcFunc) DbcFunc {
	return func(ctx context.Context, client databroker.DataBrokerServiceClient) error {
		srv := &leaser{
			client: client,
			funcs:  funcs,
		}
		leaser := databroker.NewLeaser("zero-ctrl", time.Second*30, srv)
		return leaser.Run(ctx)
	}
}
