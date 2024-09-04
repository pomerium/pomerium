package controller

import (
	"context"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type leaser struct {
	client databroker.DataBrokerServiceClient
	funcs  []func(context.Context, databroker.DataBrokerServiceClient) error
}

// GetDataBrokerServiceClient implements the databroker.LeaseHandler interface.
func (c *leaser) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return c.client
}

// RunLeased implements the databroker.LeaseHandler interface.
func (c *leaser) RunLeased(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	for _, fn := range c.funcs {
		fn := fn
		eg.Go(func() error { return fn(ctx, c.client) })
	}
	err := eg.Wait()
	return err
}

func WithLease(
	funcs ...func(context.Context, databroker.DataBrokerServiceClient) error,
) func(context.Context, databroker.DataBrokerServiceClient) error {
	return func(ctx context.Context, client databroker.DataBrokerServiceClient) error {
		srv := &leaser{
			client: client,
			funcs:  funcs,
		}
		leaser := databroker.NewLeaser("zero-ctrl", time.Second*30, srv)
		return leaser.Run(ctx)
	}
}

type LeaseStatus struct {
	v atomic.Bool
}

func (w *LeaseStatus) HasLease() bool {
	return w.v.Load()
}

func (w *LeaseStatus) MonitorLease(ctx context.Context, _ databroker.DataBrokerServiceClient) error {
	w.v.Store(true)
	<-ctx.Done()
	w.v.Store(false)
	return context.Cause(ctx)
}
