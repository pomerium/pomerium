package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var (
	sessionTypeURL = protoutil.GetTypeURL(new(session.Session))
)

// CurrentUsers returns a list of currently active user IDs from the databroker
func CurrentUsers(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
) ([]string, error) {
	records, _, _, err := databroker.InitialSync(ctx, client, &databroker.SyncLatestRequest{
		Type: sessionTypeURL,
	})
	if err != nil {
		return nil, fmt.Errorf("fetching sessions: %w", err)
	}

	var users []string
	utcNow := time.Now().UTC()
	threshold := time.Date(utcNow.Year(), utcNow.Month(), utcNow.Day(), utcNow.Hour(), 0, 0, 0, time.UTC)

	for _, record := range records {
		var s session.Session
		err := record.GetData().UnmarshalTo(&s)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling session: %w", err)
		}
		if s.UserId == "" { // session creation is in progress
			continue
		}
		if s.AccessedAt == nil {
			continue
		}
		if s.AccessedAt.AsTime().Before(threshold) {
			continue
		}
		users = append(users, s.UserId)
	}

	return users, nil
}
