package manager

import (
	"context"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type dataBrokerSyncer struct {
	cfg *atomicConfig

	update chan<- updateRecordsMessage
	clear  chan<- struct{}

	syncer *databroker.Syncer
}

func newDataBrokerSyncer(
	ctx context.Context,
	cfg *atomicConfig,
	update chan<- updateRecordsMessage,
	clear chan<- struct{},
) *dataBrokerSyncer {
	syncer := &dataBrokerSyncer{
		cfg: cfg,

		update: update,
		clear:  clear,
	}
	syncer.syncer = databroker.NewSyncer("identity_manager", syncer)
	return syncer
}

func (syncer *dataBrokerSyncer) Run(ctx context.Context) (err error) {
	return syncer.syncer.Run(ctx)
}

func (syncer *dataBrokerSyncer) ClearRecords(ctx context.Context) {
	select {
	case <-ctx.Done():
	case syncer.clear <- struct{}{}:
	}
}

func (syncer *dataBrokerSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return syncer.cfg.Load().dataBrokerClient
}

func (syncer *dataBrokerSyncer) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	select {
	case <-ctx.Done():
	case syncer.update <- updateRecordsMessage{records: records}:
	}
}
