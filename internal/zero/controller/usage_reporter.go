package controller

import (
	"context"
	"sync"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	sdk "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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
}

func newUsageReporter(api *sdk.API) *usageReporter {
	return &usageReporter{
		api:      api,
		byUserID: make(map[string]usageReporterRecord),
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

	log.Info(ctx).Int("users", len(req.Users)).Msg("reporting usage")

	// if there were no updates there's nothing to do
	if len(req.Users) == 0 {
		return nil
	}

	return ur.api.ReportUsage(ctx, req)
}

func (ur *usageReporter) run(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	timer := time.NewTicker(time.Hour)
	defer timer.Stop()

	for {
		err := ur.runOnce(ctx, client)
		if err != nil {
			log.Error(ctx).Err(err).Msg("failed to report usage")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (ur *usageReporter) runOnce(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	updated, err := ur.update(ctx, client)
	if err != nil {
		return err
	}

	err = ur.report(ctx, updated)
	if err != nil {
		return err
	}

	return nil
}

func (ur *usageReporter) update(ctx context.Context, client databroker.DataBrokerServiceClient) ([]usageReporterRecord, error) {
	updatedUserIDs := map[string]struct{}{}

	ur.mu.Lock()
	defer ur.mu.Unlock()

	// delete old records
	now := time.Now()
	for userID, r := range ur.byUserID {
		if r.accessedAt.Add(24 * time.Hour).Before(now) {
			delete(ur.byUserID, userID)
		}
	}

	// create records for all the sessions
	for s, err := range databroker.IterateAll[session.Session](ctx, client) {
		if err != nil {
			return nil, err
		}

		userID := s.Object.GetUserId()
		if userID == "" {
			continue
		}

		r := ur.byUserID[userID]
		nr := r
		nr.accessedAt = latest(nr.accessedAt, s.Object.GetIssuedAt().AsTime())
		nr.userID = userID
		if r != nr {
			updatedUserIDs[userID] = struct{}{}
			ur.byUserID[userID] = nr
		}
	}

	// fill in user names and emails
	for u, err := range databroker.IterateAll[user.User](ctx, client) {
		if err != nil {
			return nil, err
		}

		userID := u.GetId()
		if userID == "" {
			continue
		}

		r, ok := ur.byUserID[userID]
		if !ok {
			// ignore sessionless users
			continue
		}
		nr := r
		nr.userDisplayName = u.Object.GetName()
		nr.userEmail = u.Object.GetEmail()
		if r != nr {
			updatedUserIDs[userID] = struct{}{}
			ur.byUserID[userID] = nr
		}
	}

	var updated []usageReporterRecord
	for key := range updatedUserIDs {
		updated = append(updated, ur.byUserID[key])
	}
	return updated, nil
}

func latest(t1, t2 time.Time) time.Time {
	if t2.After(t1) {
		return t2
	}
	return t1
}
