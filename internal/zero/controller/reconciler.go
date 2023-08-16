package controller

import (
	"context"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/reconciler"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var now time.Time // for testing

func (c *controller) RunReconciler(ctx context.Context) error {
	now = time.Now()
	leaser := databroker.NewLeaser("zero-reconciler", c.cfg.reconcilerLeaseDuration, c)
	return leaser.Run(ctx)
}

// RunLeased implements the databroker.Leaser interface.
func (c *controller) RunLeased(ctx context.Context) error {
	log.Ctx(ctx).Info().
		Str("lease acquired in", time.Since(now).String()).
		Msg("starting reconciler (lease acquired)")
	return reconciler.Run(ctx,
		reconciler.WithAPI(c.api),
		reconciler.WithDataBrokerClient(c.GetDataBrokerServiceClient()),
	)
}
