package authorize

import (
	"context"
	"sync"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type dataBrokerSyncer struct {
	*databroker.Syncer
	authorize  *Authorize
	signalOnce sync.Once
}

func newDataBrokerSyncer(authorize *Authorize) *dataBrokerSyncer {
	syncer := &dataBrokerSyncer{
		authorize: authorize,
	}
	return syncer
}

func (syncer *dataBrokerSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return syncer.authorize.state.Load().dataBrokerClient
}

func (syncer *dataBrokerSyncer) ClearRecords(ctx context.Context) {
	syncer.authorize.store.ClearRecords()
}

func (syncer *dataBrokerSyncer) UpdateRecords(ctx context.Context, records []*databroker.Record) {
	for _, record := range records {
		syncer.authorize.store.UpdateRecord(record)
	}

	// the first time we update records we signal the initial sync
	syncer.signalOnce.Do(func() {
		close(syncer.authorize.dataBrokerInitialSync)
	})
}
