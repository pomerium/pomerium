// Package usagereporter reports usage for a cluster.
package usagereporter

import (
	"context"
	"sync"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	sdk "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/zero/cluster"
)

type usageReporterRecord struct {
	userID         string
	userEmail      string
	lastSignedInAt time.Time
}

// A UsageReporter reports usage to the zero api.
type UsageReporter struct {
	api            *sdk.API
	organizationID string

	mu       sync.Mutex
	byUserID map[string]usageReporterRecord
	updates  map[string]struct{}
}

// New creates a new UsageReporter.
func New(api *sdk.API, organizationID string) *UsageReporter {
	return &UsageReporter{
		api:            api,
		organizationID: organizationID,
		byUserID:       make(map[string]usageReporterRecord),
		updates:        make(map[string]struct{}),
	}
}

// Run runs the usage reporter.
func (ur *UsageReporter) Run(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	// first initialize the user collection
	serverVersion, latestRecordVersion, err := ur.runInit(ctx, client)
	if err != nil {
		return err
	}

	// run the continuous sync calls and periodically report usage
	return ur.runSync(ctx, client, serverVersion, latestRecordVersion)
}

func (ur *UsageReporter) report(ctx context.Context, records []usageReporterRecord) error {
	req := cluster.ReportUsageRequest{}
	for _, record := range records {
		req.Users = append(req.Users, cluster.ReportUsageUser{
			LastSignedInAt:    record.lastSignedInAt,
			PseudonymousEmail: cryptutil.Pseudonymize(ur.organizationID, record.userEmail),
			PseudonymousId:    cryptutil.Pseudonymize(ur.organizationID, record.userID),
		})
	}
	return backoff.Retry(func() error {
		log.Debug(ctx).Int("updated-users", len(req.Users)).Msg("reporting usage")
		err := ur.api.ReportUsage(ctx, req)
		if err != nil {
			log.Warn(ctx).Err(err).Msg("error reporting usage")
		}
		return err
	}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))
}

func (ur *UsageReporter) runInit(ctx context.Context, client databroker.DataBrokerServiceClient) (serverVersion, latestRecordVersion uint64, err error) {
	_, _, err = databroker.SyncLatestRecords(ctx, client, ur.onUpdateSession)
	if err != nil {
		return 0, 0, err
	}

	serverVersion, latestRecordVersion, err = databroker.SyncLatestRecords(ctx, client, ur.onUpdateUser)
	if err != nil {
		return 0, 0, err
	}

	return serverVersion, latestRecordVersion, nil
}

func (ur *UsageReporter) runSync(ctx context.Context, client databroker.DataBrokerServiceClient, serverVersion, latestRecordVersion uint64) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return databroker.SyncRecords(ctx, client, serverVersion, latestRecordVersion, ur.onUpdateSession)
	})
	eg.Go(func() error {
		return databroker.SyncRecords(ctx, client, serverVersion, latestRecordVersion, ur.onUpdateUser)
	})
	eg.Go(func() error {
		return ur.runReporter(ctx)
	})
	return eg.Wait()
}

func (ur *UsageReporter) runReporter(ctx context.Context) error {
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

		if len(records) > 0 {
			err := ur.report(ctx, records)
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

func (ur *UsageReporter) onUpdateSession(s *session.Session) {
	userID := s.GetUserId()
	if userID == "" {
		// ignore sessions without a user id
		return
	}

	ur.mu.Lock()
	defer ur.mu.Unlock()

	r := ur.byUserID[userID]
	nr := r
	nr.lastSignedInAt = latest(nr.lastSignedInAt, s.GetIssuedAt().AsTime())
	nr.userID = userID
	if nr != r {
		ur.byUserID[userID] = nr
		ur.updates[userID] = struct{}{}
	}
}

func (ur *UsageReporter) onUpdateUser(u *user.User) {
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
