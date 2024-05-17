package healthcheck

import (
	"context"
	"fmt"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
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
		forceCheck:       make(chan struct{}, 1),
	}
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { c.Scheduler(ctx); return nil })
	eg.Go(func() error { return c.ConfigSyncer(ctx) })
	return eg.Wait()
}

type checker struct {
	bootstrap        config.Source
	databrokerClient databroker.DataBrokerServiceClient
	forceCheck       chan struct{}
	configs          atomic.Value
}

func getConfig(records []*databroker.Record) ([]*configpb.Config, error) {
	var cfgs []*configpb.Config
	for _, record := range records {
		cfg := new(configpb.Config)
		if err := record.Data.UnmarshalTo(cfg); err != nil {
			return nil, fmt.Errorf("error unmarshalling config: %w", err)
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs, nil
}
