package healthcheck

import (
	"context"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func RunChecks(
	ctx context.Context,
	bootstrap config.Source,
	databrokerClient databroker.DataBrokerServiceClient,
) error {
	c := &checker{
		bootstrap:        bootstrap,
		databrokerClient: databrokerClient,
	}
	return c.run(ctx)
}

type checker struct {
	bootstrap        config.Source
	databrokerClient databroker.DataBrokerServiceClient
}

const runHealthChecksInterval = time.Minute * 30

func (c *checker) run(ctx context.Context) error {
	tm := time.NewTimer(runHealthChecksInterval)
	defer tm.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tm.C:
			c.CheckRoutes(ctx)
			tm.Reset(runHealthChecksInterval)
		}
	}
}
