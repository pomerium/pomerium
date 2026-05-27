package databrokerutil

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// InitialSync performs a sync latest and then returns all the results.
func InitialSync(
	ctx context.Context,
	client databrokerpb.DataBrokerServiceClient,
	req *databrokerpb.SyncLatestRequest,
) (records []*databrokerpb.Record, options []*databrokerpb.TypedOptions, recordVersion, serverVersion uint64, err error) {
	defer func() {
		if err != nil {
			health.ReportError(health.DatabrokerInitialSync, err)
		} else {
			health.ReportRunning(health.DatabrokerInitialSync)
		}
	}()
	stream, err := client.SyncLatest(ctx, req)
	if err != nil {
		return nil, nil, 0, 0, err
	}

loop:
	for {
		res, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			break loop
		case err != nil:
			return nil, nil, 0, 0, fmt.Errorf("error receiving record: %w", err)
		}

		switch res := res.GetResponse().(type) {
		case *databrokerpb.SyncLatestResponse_Versions:
			recordVersion = res.Versions.GetLatestRecordVersion()
			serverVersion = res.Versions.GetServerVersion()
		case *databrokerpb.SyncLatestResponse_Record:
			records = append(records, res.Record)
		case *databrokerpb.SyncLatestResponse_Options:
			options = append(options, res.Options)
		}
	}

	return records, options, recordVersion, serverVersion, nil
}

// SyncRecords calls fn for every record using Sync.
func SyncRecords[T any, TMessage interface {
	*T
	proto.Message
}](
	ctx context.Context,
	client databrokerpb.DataBrokerServiceClient,
	serverVersion, latestRecordVersion uint64,
	fn func(TMessage),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var msg TMessage = new(T)
	stream, err := client.Sync(ctx, &databrokerpb.SyncRequest{
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

		switch res := res.Response.(type) {
		case *databrokerpb.SyncResponse_Record:
			msg = new(T)
			err = res.Record.GetData().UnmarshalTo(msg)
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
}

// SyncLatestRecords calls fn for every record using SyncLatest.
func SyncLatestRecords[T any, TMessage interface {
	*T
	proto.Message
}](
	ctx context.Context,
	client databrokerpb.DataBrokerServiceClient,
	fn func(TMessage),
) (serverVersion, latestRecordVersion uint64, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var msg TMessage = new(T)
	stream, err := client.SyncLatest(ctx, &databrokerpb.SyncLatestRequest{
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
		case *databrokerpb.SyncLatestResponse_Versions:
			serverVersion = res.Versions.GetServerVersion()
			latestRecordVersion = res.Versions.GetLatestRecordVersion()
		case *databrokerpb.SyncLatestResponse_Record:
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
		}
	}
}
