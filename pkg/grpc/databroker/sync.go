package databroker

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// SyncRecords calls fn for every record using Sync.
func SyncRecords[T any, TMessage interface {
	*T
	proto.Message
}](
	ctx context.Context,
	client DataBrokerServiceClient,
	serverVersion, latestRecordVersion uint64,
	fn func(TMessage),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var msg TMessage = new(T)
	streamType := protoutil.GetTypeURL(msg)
	log.Ctx(ctx).Debug().Str("record-type", streamType).Msg("starting record sync stream")
	stream, err := client.Sync(ctx, &SyncRequest{
		Type:          protoutil.GetTypeURL(msg),
		ServerVersion: serverVersion,
		RecordVersion: latestRecordVersion,
	})
	if err != nil {
		return fmt.Errorf("error syncing %T: %w", msg, err)
	}

	for {
		res, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return fmt.Errorf("error receiving record for %T: %w", msg, err)
		}
		if res.GetRecord().GetType() != streamType {
			log.Ctx(ctx).Debug().
				Str("stream-type", streamType).
				Str("incoming-type", res.GetRecord().GetType()).
				Str("record-id", res.GetRecord().GetId()).
				Msg("mismatched stream types")
			continue
		}

		msg = new(T)
		err = res.GetRecord().GetData().UnmarshalTo(msg)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("record-type", res.Record.Type).
				Str("record-id", res.Record.GetId()).
				Msgf("unexpected data in %T stream", msg)
			continue
		}

		fn(msg)
	}
}

// SyncLatestRecords calls fn for every record using SyncLatest.
func SyncLatestRecords[T any, TMessage interface {
	*T
	proto.Message
}](
	ctx context.Context,
	client DataBrokerServiceClient,
	fn func(TMessage),
) (serverVersion, latestRecordVersion uint64, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var msg TMessage = new(T)
	stream, err := client.SyncLatest(ctx, &SyncLatestRequest{
		Type: protoutil.GetTypeURL(msg),
	})
	if err != nil {
		return 0, 0, fmt.Errorf("error syncing latest %T: %w", msg, err)
	}

	for {
		res, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return serverVersion, latestRecordVersion, nil
		case err != nil:
			return 0, 0, fmt.Errorf("error receiving record for latest %T: %w", msg, err)
		}

		switch res := res.GetResponse().(type) {
		case *SyncLatestResponse_Versions:
			serverVersion = res.Versions.GetServerVersion()
			latestRecordVersion = res.Versions.GetLatestRecordVersion()
		case *SyncLatestResponse_Record:
			msg = new(T)
			err = res.Record.GetData().UnmarshalTo(msg)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).
					Str("record-type", res.Record.Type).
					Str("record-id", res.Record.GetId()).
					Msgf("unexpected data in latest %T stream", msg)
				continue
			}

			fn(msg)
		default:
			panic(fmt.Sprintf("unexpected response: %T", res))
		}
	}
}
