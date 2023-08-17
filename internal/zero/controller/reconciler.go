package controller

import (
	"context"

	"github.com/pomerium/pomerium/internal/zero/reconciler"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func (c *controller) RunReconciler(ctx context.Context) error {
	leaser := databroker.NewLeaser("zero-reconciler", c.cfg.reconcilerLeaseDuration, c)
	return leaser.Run(ctx)
}

// RunLeased implements the databroker.Leaser interface.
func (c *controller) RunLeased(ctx context.Context) error {
	return reconciler.Run(ctx,
		reconciler.WithAPI(c.api),
		reconciler.WithDataBrokerClient(c.GetDataBrokerServiceClient()),
	)
}
