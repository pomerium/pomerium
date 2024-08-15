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

type Checker struct {
	bootstrap        config.Source
	databrokerClient databroker.DataBrokerServiceClient
	forceCheck       chan struct{}
	configs          atomic.Value
}

func NewChecker(
	bootstrap config.Source,
	databrokerClient databroker.DataBrokerServiceClient,
) *Checker {
	c := &Checker{
		bootstrap:        bootstrap,
		databrokerClient: databrokerClient,
		forceCheck:       make(chan struct{}, 1),
	}
	return c
}

func (c *Checker) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { c.Scheduler(ctx); return nil })
	eg.Go(func() error { return c.ConfigSyncer(ctx) })
	return eg.Wait()
}

func (c *Checker) ForceCheck() {
	select {
	case c.forceCheck <- struct{}{}:
	default:
	}
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
