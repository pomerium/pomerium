package sessions

import (
	"context"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/sets"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

// CurrentUsers returns a list of users active within the current UTC day
func CurrentUsers(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
) ([]string, error) {
	users := sets.NewHash[string]()
	utcNow := time.Now().UTC()
	threshold := time.Date(utcNow.Year(), utcNow.Month(), utcNow.Day(), 0, 0, 0, 0, time.UTC)

	for s, err := range databroker.IterateAll[session.Session](ctx, client) {
		if err != nil {
			return nil, fmt.Errorf("error fetching sessions: %w", err)
		}

		if s.Object.GetUserId() == "" { // session creation is in progress
			continue
		}
		if s.Object.GetAccessedAt() == nil {
			continue
		}
		if s.Object.GetAccessedAt().AsTime().Before(threshold) {
			continue
		}
		users.Add(s.Object.GetUserId())
	}

	return users.Items(), nil
}
