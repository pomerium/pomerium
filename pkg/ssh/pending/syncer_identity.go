package pending

import (
	"context"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/rs/zerolog/log"
)

type sessionBindingSyncerHandler struct {
	tr     *pendingSessionTracker
	client databroker.DataBrokerServiceClient
	cache  *sessionCache
}

func newIdentitySyncerHandler(
	cache *sessionCache,
	tr *pendingSessionTracker,
	client databroker.DataBrokerServiceClient,
) *sessionBindingSyncerHandler {
	return &sessionBindingSyncerHandler{
		client: client,
		tr:     tr,
		cache:  cache,
	}
}

// ClearRecords implements databroker.SyncerHandler.
func (mgr *sessionBindingSyncerHandler) ClearRecords(ctx context.Context) {
	mgr.tr.mu.Lock()
	defer mgr.tr.mu.Unlock()

	for _, meta := range mgr.tr.sess {
		meta.Close()
	}
}

// GetDataBrokerServiceClient implements databroker.SyncerHandler.
func (mgr *sessionBindingSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.client
}

func (mgr *sessionBindingSyncerHandler) fetchRelatedRecords(ctx context.Context, record *databroker.Record) []*databroker.Record {
	var binding session.SessionBinding
	if err := record.GetData().UnmarshalTo(&binding); err != nil {
		panic(err)
	}
	recordsToInvalidate := []*databroker.Record{}
	sessionRes, err := mgr.client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.Session",
		Id:   binding.SessionId,
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
	return recordsToInvalidate
}

func (mgr *sessionBindingSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	// TODO : this logic probably needs work. For example if there are somehow out of date records in this list.
	log.Warn().Uint64("serverVersion", serverVersion).Int("numRecords", len(records)).Msg("syncing session bindings")
	for _, record := range records {
		if record.DeletedAt != nil {
			continue
		}
		sessionID := record.Id
		recordsToInvalidate := mgr.fetchRelatedRecords(ctx, record)
		mgr.cache.PutSession(SessionID(sessionID), recordsToInvalidate)
		mgr.tr.SetRecords(sessionID, recordsToInvalidate)
	}
}
