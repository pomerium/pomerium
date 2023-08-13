package controller

import (
	"context"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/reconciler"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func (c *controller) RunReconciler(ctx context.Context) error {
	leaser := databroker.NewLeaser("zero-reconciler", c.cfg.reconcilerLeaseDuration, c)
	return leaser.Run(ctx)
}

// RunLeased implements the databroker.Leaser interface.
func (c *controller) RunLeased(ctx context.Context) error {
	log.Ctx(ctx).Info().Msg("starting reconciler")
	return reconciler.Run(ctx,
		reconciler.WithAPI(c.api),
		reconciler.WithConnectMux(c.connectMux),
		reconciler.WithDataBrokerClient(c.GetDataBrokerServiceClient()),
	)
}
