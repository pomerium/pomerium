package manager

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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

	updatedDirectoryGroup chan<- *directory.Group
	updatedDirectoryUser  chan<- *directory.User
	updatedSession        chan<- sessionMessage
	updatedUser           chan<- userMessage
	clear                 chan<- struct{}

	syncer *databroker.Syncer
}

func newDataBrokerSyncer(
	cfg *atomicConfig,
	log zerolog.Logger,
	updatedDirectoryGroup chan<- *directory.Group,
	updatedDirectoryUser chan<- *directory.User,
	updatedSession chan<- sessionMessage,
	updatedUser chan<- userMessage,
	clear chan<- struct{},
) *dataBrokerSyncer {
	syncer := &dataBrokerSyncer{
		cfg: cfg,
		log: log,

		updatedDirectoryGroup: updatedDirectoryGroup,
		updatedDirectoryUser:  updatedDirectoryUser,
		updatedSession:        updatedSession,
		updatedUser:           updatedUser,
		clear:                 clear,
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
	for _, record := range records {
		err := syncer.handleRecord(ctx, record)
		if err != nil {
			log.Warn().Err(err).Msg("databroker record update error")
		}
	}
}

func (syncer *dataBrokerSyncer) handleRecord(ctx context.Context, record *databroker.Record) error {
	switch record.GetType() {
	case directoryGroupTypeURL:
		var pbDirectoryGroup directory.Group
		err := record.GetData().UnmarshalTo(&pbDirectoryGroup)
		if err != nil {
			return fmt.Errorf("error unmarshaling directory group: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case syncer.updatedDirectoryGroup <- &pbDirectoryGroup:
		}
	case directoryUserTypeURL:
		var pbDirectoryUser directory.User
		err := record.GetData().UnmarshalTo(&pbDirectoryUser)
		if err != nil {
			return fmt.Errorf("error unmarshaling directory user: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case syncer.updatedDirectoryUser <- &pbDirectoryUser:
		}
	case sessionTypeURL:
		var pbSession session.Session
		err := record.GetData().UnmarshalTo(&pbSession)
		if err != nil {
			return fmt.Errorf("error unmarshaling session: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case syncer.updatedSession <- sessionMessage{record: record, session: &pbSession}:
		}
	case userTypeURL:
		var pbUser user.User
		err := record.GetData().UnmarshalTo(&pbUser)
		if err != nil {
			return fmt.Errorf("error unmarshaling user: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case syncer.updatedUser <- userMessage{record: record, user: &pbUser}:
		}
	}
	return nil
}
