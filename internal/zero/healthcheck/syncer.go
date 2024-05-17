package healthcheck

import (
	"context"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func (c *checker) ConfigSyncer(ctx context.Context) error {
	syncer := databroker.NewSyncer("zero-health-check", c, databroker.WithTypeURL(protoutil.GetTypeURL(new(configpb.Config))))
	return syncer.Run(ctx)
}

func (c *checker) GetConfigs() []*configpb.Config {
	configs := c.configs.Load()
	if configs == nil {
		return nil
	}
	return configs.([]*configpb.Config)
}

// ClearRecords implements databroker.Syncer interface
func (c *checker) ClearRecords(_ context.Context) {
	c.configs.Store([]*configpb.Config{})
}

// UpdateRecords implements databroker.Syncer interface
func (c *checker) UpdateRecords(_ context.Context, _ uint64, records []*databroker.Record) {
	if len(records) == 0 {
		return
	}

	cfgs, err := getConfig(records)
	if err != nil {
		health.ReportInternalError(health.RoutesReachable, err)
		return
	}
	c.configs.Store(cfgs)
	select {
	case c.forceCheck <- struct{}{}:
	default:
	}
}

// GetDataBrokerServiceClient implements databroker.Syncer interface
func (c *checker) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return c.databrokerClient
}
