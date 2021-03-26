package authorize

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

const (
	forceSyncRecordMaxWait      = 5 * time.Second
	forceSyncRecordPollInterval = 100 * time.Millisecond
)

type sessionOrServiceAccount interface {
	GetUserId() string
}

type dataBrokerSyncer struct {
	*databroker.Syncer
	authorize  *Authorize
	signalOnce sync.Once
}

func newDataBrokerSyncer(authorize *Authorize) *dataBrokerSyncer {
	syncer := &dataBrokerSyncer{
		authorize: authorize,
	}
	syncer.Syncer = databroker.NewSyncer(syncer)
	return syncer
}

func (syncer *dataBrokerSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return syncer.authorize.state.Load().dataBrokerClient
}

func (syncer *dataBrokerSyncer) ClearRecords(ctx context.Context) {
	syncer.authorize.store.ClearRecords()
}

func (syncer *dataBrokerSyncer) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	for _, record := range records {
		syncer.authorize.store.UpdateRecord(serverVersion, record)
	}

	// the first time we update records we signal the initial sync
	syncer.signalOnce.Do(func() {
		close(syncer.authorize.dataBrokerInitialSync)
	})
}

func (a *Authorize) forceSync(ctx context.Context, ss *sessions.State) (*user.User, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSync")
	defer span.End()
	if ss == nil {
		return nil, nil
	}
	s := a.forceSyncSession(ctx, ss.ID)
	if s == nil {
		return nil, errors.New("session not found")
	}
	u := a.forceSyncUser(ctx, s.GetUserId())
	return u, nil
}

func (a *Authorize) forceSyncSession(ctx context.Context, sessionID string) sessionOrServiceAccount {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSyncSession")
	defer span.End()

	s, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(session.Session)), sessionID).(*session.Session)
	if ok {
		return s
	}

	sa, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(user.ServiceAccount)), sessionID).(*user.ServiceAccount)
	if ok {
		return sa
	}

	// wait for the session to show up
	a.waitForRecordSync(ctx,
		grpcutil.GetTypeURL(new(session.Session)), sessionID,
		forceSyncRecordMaxWait, forceSyncRecordPollInterval,
	)
	s, ok = a.store.GetRecordData(grpcutil.GetTypeURL(new(session.Session)), sessionID).(*session.Session)
	if !ok {
		return nil
	}
	return s
}

func (a *Authorize) forceSyncUser(ctx context.Context, userID string) *user.User {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSyncUser")
	defer span.End()

	u, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(user.User)), userID).(*user.User)
	if ok {
		return u
	}

	// wait for the user to show up
	a.waitForRecordSync(ctx,
		grpcutil.GetTypeURL(new(user.User)), userID,
		forceSyncRecordMaxWait, forceSyncRecordPollInterval,
	)
	u, ok = a.store.GetRecordData(grpcutil.GetTypeURL(new(user.User)), userID).(*user.User)
	if !ok {
		return nil
	}
	return u
}

// waitForRecordSync waits for the first sync of a record to complete
func (a *Authorize) waitForRecordSync(ctx context.Context,
	recordTypeURL, recordID string,
	maxWait, pollInterval time.Duration,
) {
	ctx, clearTimeout := context.WithTimeout(ctx, maxWait)
	defer clearTimeout()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		current := a.store.GetRecordData(recordTypeURL, recordID)
		if current != nil {
			// record found, so it's already synced
			return
		}

		_, err := a.state.Load().dataBrokerClient.Get(ctx, &databroker.GetRequest{
			Type: recordTypeURL,
			Id:   recordID,
		})
		if status.Code(err) == codes.NotFound {
			// record not found, so no need to wait
			return
		} else if err != nil {
			log.Error().
				Err(err).
				Str("type", recordTypeURL).
				Str("id", recordID).
				Msg("authorize: error retrieving record")
		}

		select {
		case <-ctx.Done():
			log.Warn().
				Str("type", recordTypeURL).
				Str("id", recordID).
				Msg("authorize: first sync of record did not complete")
			return
		case <-ticker.C:
		}
	}
}
