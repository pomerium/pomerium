package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/directory"
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

	backoff *backoff.ExponentialBackOff
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
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	return &dataBrokerSyncer{
		cfg: cfg,
		log: log,

		updatedDirectoryGroup: updatedDirectoryGroup,
		updatedDirectoryUser:  updatedDirectoryUser,
		updatedSession:        updatedSession,
		updatedUser:           updatedUser,
		clear:                 clear,

		backoff: bo,
	}
}

func (syncer *dataBrokerSyncer) Run(ctx context.Context) (err error) {
	var recordVersion, serverVersion uint64
	for {
		if serverVersion == 0 {
			recordVersion, serverVersion, err = syncer.init(ctx)
		} else {
			err = syncer.sync(ctx, &recordVersion, &serverVersion)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(syncer.backoff.NextBackOff()):
		}
	}
}

func (syncer *dataBrokerSyncer) init(ctx context.Context) (recordVersion uint64, serverVersion uint64, err error) {
	syncer.log.Info().Msg("initializing directory data")

	select {
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	case syncer.clear <- struct{}{}:
	}

	records, serverVersion, err := databroker.InitialSync(ctx, syncer.cfg.Load().dataBrokerClient)
	if err != nil {
		return 0, 0, fmt.Errorf("error getting all directory users: %w", err)
	}

	syncer.backoff.Reset()

	for _, record := range records {
		err = syncer.handleRecord(ctx, record)
		if err != nil {
			return 0, 0, err
		}
		if record.GetVersion() > recordVersion {
			recordVersion = record.GetVersion()
		}
	}

	syncer.log.Info().
		Uint64("record_version", recordVersion).
		Uint64("server_version", serverVersion).
		Int("count", len(records)).
		Msg("initialized directory data")

	return recordVersion, serverVersion, nil
}

func (syncer *dataBrokerSyncer) sync(ctx context.Context, recordVersion, serverVersion *uint64) error {
	stream, err := syncer.cfg.Load().dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
		RecordVersion: *recordVersion,
		ServerVersion: *serverVersion,
	})
	if status.Code(err) == codes.Aborted {
		// reset the server version to re-init
		*serverVersion = 0
		*recordVersion = 0
		return err
	}
	if err != nil {
		return err
	}

	syncer.backoff.Reset()

	for {
		res, err := stream.Recv()
		if err != nil {
			return err
		}

		*recordVersion = res.GetRecord().GetVersion()
		*serverVersion = res.GetServerVersion()

		err = syncer.handleRecord(ctx, res.GetRecord())
		if err != nil {
			return err
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
