package manager

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var (
	directoryGroupTypeURL = "type.googleapis.com/directory.Group"
	directoryUserTypeURL  = "type.googleapis.com/directory.User"
	sessionTypeURL        = "type.googleapis.com/session.Session"
	userTypeURL           = "type.googleapis.com/user.User"
)

type dataBrokerSyncer struct {
	cfg *atomicConfig
	log zerolog.Logger

	update chan<- updateRecordsMessage
	clear  chan<- struct{}

	syncer *databroker.Syncer
}

func newDataBrokerSyncer(
	cfg *atomicConfig,
	log zerolog.Logger,
	update chan<- updateRecordsMessage,
	clear chan<- struct{},
) *dataBrokerSyncer {
	syncer := &dataBrokerSyncer{
		cfg: cfg,
		log: log,

		update: update,
		clear:  clear,
	}
	syncer.syncer = databroker.NewSyncer(syncer)
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

func (syncer *dataBrokerSyncer) UpdateRecords(ctx context.Context, records []*databroker.Record) {
	select {
	case <-ctx.Done():
	case syncer.update <- updateRecordsMessage{records: records}:
	}
}
