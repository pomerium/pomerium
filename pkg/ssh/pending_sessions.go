package ssh

import (
	"context"
	"sync"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type PendingSessionManager struct {
	client databroker.DataBrokerServiceClient

	done chan struct{}
	err  error

	waiters sync.Map
}

// ClearRecords implements databroker.SyncerHandler.
func (mgr *PendingSessionManager) ClearRecords(ctx context.Context) {
	mgr.waiters.Range(func(k, v any) bool {
		close(v.(chan struct{}))
		mgr.waiters.Delete(k)
		return true
	})
}

// GetDataBrokerServiceClient implements databroker.SyncerHandler.
func (mgr *PendingSessionManager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.client
}

// UpdateRecords implements databroker.SyncerHandler.
func (mgr *PendingSessionManager) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	for _, record := range records {
		if record.DeletedAt == nil {
			continue
		}
		var pendingSession session.PendingSession
		if err := record.GetData().UnmarshalTo(&pendingSession); err != nil {
			panic(err)
		}
		if v, ok := mgr.waiters.LoadAndDelete(pendingSession.UserCode); ok {
			recordsToInvalidate := []*databroker.Record{}
			sessionRes, err := mgr.client.Get(ctx, &databroker.GetRequest{
				Type: "type.googleapis.com/session.Session",
				Id:   pendingSession.PredeterminedSessionId,
			})
			if err == nil {
				recordsToInvalidate = append(recordsToInvalidate, sessionRes.Record)
			}
			var s session.Session
			err = sessionRes.GetRecord().GetData().UnmarshalTo(&s)
			if err == nil {
				userRes, err := mgr.client.Get(ctx, &databroker.GetRequest{
					Type: "type.googleapis.com/user.User",
					Id:   s.GetUserId(),
				})
				if err == nil {
					recordsToInvalidate = append(recordsToInvalidate, userRes.Record)
				}
			}
			v.(chan []*databroker.Record) <- recordsToInvalidate
		}
	}
}

func NewPendingSessionManager(ctx context.Context, client databroker.DataBrokerServiceClient) *PendingSessionManager {
	mgr := &PendingSessionManager{
		client: client,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(mgr.done)
		mgr.err = mgr.run(ctx)
	}()
	return mgr
}

func (mgr *PendingSessionManager) run(ctx context.Context) error {
	syncer := databroker.NewSyncer(ctx, "pending-session-mgr", mgr, databroker.WithTypeURL("type.googleapis.com/session.PendingSession"))
	return syncer.Run(ctx)
}

func (mgr *PendingSessionManager) Insert(ctx context.Context, pendingSession *session.PendingSession) (chan []*databroker.Record, error) {
	data := protoutil.NewAny(pendingSession)
	c := make(chan []*databroker.Record, 1)
	_, alreadyExists := mgr.waiters.LoadOrStore(pendingSession.UserCode, c)
	if alreadyExists {
		panic("bug: PendingSessionManager.Insert() called twice for the same session ID")
	}
	_, err := mgr.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: data.GetTypeUrl(),
			Id:   pendingSession.UserCode,
			Data: data,
		}},
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (mgr *PendingSessionManager) Done() <-chan struct{} {
	return mgr.done
}

// Err() is guaranteed to return a non-nil error after Done() is closed.
func (mgr *PendingSessionManager) Err() error {
	select {
	case <-mgr.done:
		if mgr.err == nil {
			panic("bug: error must not be nil")
		}
	default:
		panic("bug: Err() called before Done() channel closed")
	}
	return mgr.err
}
