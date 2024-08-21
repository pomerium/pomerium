package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	sdk "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/zero/cluster"
)

type usageReporterRecord struct {
	userID          string
	userDisplayName string
	userEmail       string
	accessedAt      time.Time
}

type usageReporter struct {
	api *sdk.API

	mu       sync.Mutex
	byUserID map[string]usageReporterRecord
	updates  map[string]struct{}
}

func newUsageReporter(api *sdk.API) *usageReporter {
	return &usageReporter{
		api:      api,
		byUserID: make(map[string]usageReporterRecord),
		updates:  make(map[string]struct{}),
	}
}

func (ur *usageReporter) report(ctx context.Context, records []usageReporterRecord) error {
	req := cluster.ReportUsageRequest{}
	for _, record := range records {
		req.Users = append(req.Users, cluster.ReportUsageUser{
			AccessedAt:  record.accessedAt,
			DisplayName: record.userDisplayName,
			Email:       record.userEmail,
			Id:          record.userID,
		})
	}
	return ur.api.ReportUsage(ctx, req)
}

func (ur *usageReporter) run(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	// first initialize the user collection
	serverVersion, latestRecordVersion, err := ur.runInit(ctx, client)
	if err != nil {
		return err
	}

	// run the continuous sync calls and periodically report usage
	return ur.runSync(ctx, client, serverVersion, latestRecordVersion)
}

func (ur *usageReporter) runInit(ctx context.Context, client databroker.DataBrokerServiceClient) (serverVersion, latestRecordVersion uint64, err error) {
	_, _, err = syncLatestRecords(ctx, client, ur.onUpdateSession)
	if err != nil {
		return 0, 0, err
	}

	serverVersion, latestRecordVersion, err = syncLatestRecords(ctx, client, ur.onUpdateUser)
	if err != nil {
		return 0, 0, err
	}

	return serverVersion, latestRecordVersion, nil
}

func (ur *usageReporter) runSync(ctx context.Context, client databroker.DataBrokerServiceClient, serverVersion, latestRecordVersion uint64) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return syncRecords(ctx, client, serverVersion, latestRecordVersion, ur.onUpdateSession)
	})
	eg.Go(func() error {
		return syncRecords(ctx, client, serverVersion, latestRecordVersion, ur.onUpdateUser)
	})
	eg.Go(func() error {
		return ur.runReporter(ctx)
	})
	return eg.Wait()
}

func (ur *usageReporter) runReporter(ctx context.Context) error {
	// every minute collect any updates and submit them to the API
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()

	for {
		// collect the updated records since last run
		ur.mu.Lock()
		records := make([]usageReporterRecord, 0, len(ur.updates))
		for userID := range ur.updates {
			records = append(records, ur.byUserID[userID])
		}
		clear(ur.updates)
		ur.mu.Unlock()

		// report the records with a backoff in case the API is temporarily unavailable
		if len(records) > 0 {
			log.Info(ctx).Int("updated-users", len(records)).Msg("reporting usage")
			err := backoff.Retry(func() error {
				err := ur.report(ctx, records)
				if err != nil {
					log.Error(ctx).Err(err).Msg("error reporting usage")
				}
				return err
			}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))
			if err != nil {
				return err
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (ur *usageReporter) onUpdateSession(s *session.Session) {
	userID := s.GetUserId()
	if userID == "" {
		// ignore sessions without a user id
		return
	}

	ur.mu.Lock()
	defer ur.mu.Unlock()

	r := ur.byUserID[userID]
	nr := r
	nr.accessedAt = latest(nr.accessedAt, s.GetIssuedAt().AsTime())
	nr.userID = userID
	if nr != r {
		ur.byUserID[userID] = nr
		ur.updates[userID] = struct{}{}
	}
}

func (ur *usageReporter) onUpdateUser(u *user.User) {
	userID := u.GetId()
	if userID == "" {
		// ignore users without a user id
		return
	}

	ur.mu.Lock()
	defer ur.mu.Unlock()

	r := ur.byUserID[userID]
	nr := r
	nr.userID = userID
	nr.userDisplayName = u.GetName()
	nr.userEmail = u.GetEmail()
	if nr != r {
		ur.byUserID[userID] = nr
		ur.updates[userID] = struct{}{}
	}
}

func latest(t1, t2 time.Time) time.Time {
	if t2.After(t1) {
		return t2
	}
	return t1
}

func syncRecords[T any, TMessage interface {
	*T
	proto.Message
}](
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	serverVersion, latestRecordVersion uint64,
	fn func(TMessage),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var msg TMessage = new(T)
	stream, err := client.Sync(ctx, &databroker.SyncRequest{
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

		msg = new(T)
		err = res.GetRecord().GetData().UnmarshalTo(msg)
		if err != nil {
			log.Error(ctx).Err(err).
				Str("record-type", res.Record.Type).
				Str("record-id", res.Record.GetId()).
				Msgf("unexpected data in %T stream", msg)
			continue
		}

		fn(msg)
	}
}

func syncLatestRecords[T any, TMessage interface {
	*T
	proto.Message
}](
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	fn func(TMessage),
) (serverVersion, latestRecordVersion uint64, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var msg TMessage = new(T)
	stream, err := client.SyncLatest(ctx, &databroker.SyncLatestRequest{
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
		case *databroker.SyncLatestResponse_Versions:
			serverVersion = res.Versions.GetServerVersion()
			latestRecordVersion = res.Versions.GetLatestRecordVersion()
		case *databroker.SyncLatestResponse_Record:
			msg = new(T)
			err = res.Record.GetData().UnmarshalTo(msg)
			if err != nil {
				log.Error(ctx).Err(err).
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
