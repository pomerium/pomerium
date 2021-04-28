package authorize

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

const (
	forceSyncRecordMaxWait = 5 * time.Second
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
	syncer.Syncer = databroker.NewSyncer("authorize", syncer)
	return syncer
}

func (syncer *dataBrokerSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return syncer.authorize.state.Load().dataBrokerClient
}

func (syncer *dataBrokerSyncer) ClearRecords(ctx context.Context) {
	syncer.authorize.stateLock.Lock()
	syncer.authorize.store.ClearRecords()
	syncer.authorize.stateLock.Unlock()
}

func (syncer *dataBrokerSyncer) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	syncer.authorize.stateLock.Lock()
	for _, record := range records {
		syncer.authorize.store.UpdateRecord(serverVersion, record)
	}
	syncer.authorize.stateLock.Unlock()

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

	ctx, clearTimeout := context.WithTimeout(ctx, forceSyncRecordMaxWait)
	defer clearTimeout()

	s, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(session.Session)), sessionID).(*session.Session)
	if ok {
		return s
	}

	sa, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(user.ServiceAccount)), sessionID).(*user.ServiceAccount)
	if ok {
		return sa
	}

	// wait for the session to show up
	record, err := a.waitForRecordSync(ctx, grpcutil.GetTypeURL(new(session.Session)), sessionID)
	if err != nil {
		return nil
	}
	s, ok = record.(*session.Session)
	if !ok {
		return nil
	}
	return s
}

func (a *Authorize) forceSyncUser(ctx context.Context, userID string) *user.User {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSyncUser")
	defer span.End()

	ctx, clearTimeout := context.WithTimeout(ctx, forceSyncRecordMaxWait)
	defer clearTimeout()

	u, ok := a.store.GetRecordData(grpcutil.GetTypeURL(new(user.User)), userID).(*user.User)
	if ok {
		return u
	}

	// wait for the user to show up
	record, err := a.waitForRecordSync(ctx, grpcutil.GetTypeURL(new(user.User)), userID)
	if err != nil {
		return nil
	}
	u, ok = record.(*user.User)
	if !ok {
		return nil
	}
	return u
}

// waitForRecordSync waits for the first sync of a record to complete
func (a *Authorize) waitForRecordSync(ctx context.Context, recordTypeURL, recordID string) (proto.Message, error) {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = time.Millisecond
	bo.MaxElapsedTime = 0
	bo.Reset()

	for {
		current := a.store.GetRecordData(recordTypeURL, recordID)
		if current != nil {
			// record found, so it's already synced
			return current, nil
		}

		_, err := a.state.Load().dataBrokerClient.Get(ctx, &databroker.GetRequest{
			Type: recordTypeURL,
			Id:   recordID,
		})
		if status.Code(err) == codes.NotFound {
			// record not found, so no need to wait
			return nil, nil
		} else if err != nil {
			log.Error(ctx).
				Err(err).
				Str("type", recordTypeURL).
				Str("id", recordID).
				Msg("authorize: error retrieving record")
			return nil, err
		}

		select {
		case <-ctx.Done():
			log.Warn(ctx).
				Str("type", recordTypeURL).
				Str("id", recordID).
				Msg("authorize: first sync of record did not complete")
			return nil, ctx.Err()
		case <-time.After(bo.NextBackOff()):
		}
	}
}
