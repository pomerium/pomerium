// Package usagereporter reports usage for a cluster.
//
// Usage is determined from session and user records in the databroker. The usage reporter
// uses SyncLatest and Sync to retrieve this data, builds a collection of records and then
// sends them to the Zero Cluster API every minute.
//
// All usage users are reported on start but only the changed users are reported while running.
// The Zero Cluster API is tolerant of redundant data.
package usagereporter

import (
	"cmp"
	"context"
	"sync"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	set "github.com/hashicorp/go-set/v3"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/zero/cluster"
)

// API is the part of the Zero Cluster API used to report usage.
type API interface {
	ReportUsage(ctx context.Context, req cluster.ReportUsageRequest) error
}

type usageReporterRecord struct {
	userID         string
	userEmail      string
	lastSignedInAt time.Time
}

// A UsageReporter reports usage to the zero api.
type UsageReporter struct {
	api            API
	organizationID string
	reportInterval time.Duration

	mu       sync.Mutex
	byUserID map[string]usageReporterRecord
	updates  *set.Set[string]
}

// New creates a new UsageReporter.
func New(api API, organizationID string, reportInterval time.Duration) *UsageReporter {
	return &UsageReporter{
		api:            api,
		organizationID: organizationID,
		reportInterval: reportInterval,

		byUserID: make(map[string]usageReporterRecord),
		updates:  set.New[string](0),
	}
}

// Run runs the usage reporter.
func (ur *UsageReporter) Run(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ctx = log.Ctx(ctx).With().Str("organization-id", ur.organizationID).Logger().WithContext(ctx)

	// first initialize the user collection
	serverVersion, latestSessionRecordVersion, latestUserRecordVersion, err := ur.runInit(ctx, client)
	if err != nil {
		return err
	}

	// run the continuous sync calls and periodically report usage
	return ur.runSync(ctx, client, serverVersion, latestSessionRecordVersion, latestUserRecordVersion)
}

func (ur *UsageReporter) report(ctx context.Context, records []usageReporterRecord) error {
	req := cluster.ReportUsageRequest{
		Users: convertUsageReporterRecords(ur.organizationID, records),
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

func (ur *UsageReporter) runInit(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
) (serverVersion, latestSessionRecordVersion, latestUserRecordVersion uint64, err error) {
	_, latestSessionRecordVersion, err = databroker.SyncLatestRecords(ctx, client, ur.onUpdateSession)
	if err != nil {
		return 0, 0, 0, err
	}

	serverVersion, latestUserRecordVersion, err = databroker.SyncLatestRecords(ctx, client, ur.onUpdateUser)
	if err != nil {
		return 0, 0, 0, err
	}

	return serverVersion, latestSessionRecordVersion, latestUserRecordVersion, nil
}

func (ur *UsageReporter) runSync(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	serverVersion, latestSessionRecordVersion, latestUserRecordVersion uint64,
) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return databroker.SyncRecords(ctx, client, serverVersion, latestSessionRecordVersion, ur.onUpdateSession)
	})
	eg.Go(func() error {
		return databroker.SyncRecords(ctx, client, serverVersion, latestUserRecordVersion, ur.onUpdateUser)
	})
	eg.Go(func() error {
		return ur.runReporter(ctx)
	})
	return eg.Wait()
}

func (ur *UsageReporter) runReporter(ctx context.Context) error {
	// every minute collect any updates and submit them to the API
	timer := time.NewTicker(ur.reportInterval)
	defer timer.Stop()

	for {
		// collect the updated records since last run
		ur.mu.Lock()
		records := make([]usageReporterRecord, 0, ur.updates.Size())
		for userID := range ur.updates.Items() {
			records = append(records, ur.byUserID[userID])
		}
		ur.updates = set.New[string](0)
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
		ur.updates.Insert(userID)
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
	nr.userEmail = cmp.Or(nr.userEmail, u.GetEmail())
	if nr != r {
		ur.byUserID[userID] = nr
		ur.updates.Insert(userID)
	}
}

func convertUsageReporterRecords(organizationID string, records []usageReporterRecord) []cluster.ReportUsageUser {
	var users []cluster.ReportUsageUser
	for _, record := range records {
		u := cluster.ReportUsageUser{
			LastSignedInAt: record.lastSignedInAt,
			PseudonymousId: cryptutil.Pseudonymize(organizationID, record.userID),
		}
		if record.userEmail != "" {
			u.PseudonymousEmail = cryptutil.Pseudonymize(organizationID, record.userEmail)
		}
		users = append(users, u)
	}
	return users
}

// latest returns the latest time.
func latest(t1, t2 time.Time) time.Time {
	if t2.After(t1) {
		return t2
	}
	return t1
}
