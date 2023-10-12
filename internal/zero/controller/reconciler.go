package controller

import (
	"context"

	"github.com/pomerium/pomerium/internal/zero/reconciler"
)

func (c *controller) RunReconciler(ctx context.Context) error {
	return reconciler.Run(ctx,
		reconciler.WithAPI(c.api),
		reconciler.WithDataBrokerClient(c.GetDataBrokerServiceClient()),
	)
}
