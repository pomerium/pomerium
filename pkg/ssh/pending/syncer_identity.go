package pending

import (
	"context"
	"log/slog"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/rs/zerolog/log"
)

type sessionBindingSyncerHandler struct {
	client databroker.DataBrokerServiceClient
	cache  *sessionCache
}

func newIdentitySyncerHandler(
	cache *sessionCache,
	client databroker.DataBrokerServiceClient,
) *sessionBindingSyncerHandler {
	return &sessionBindingSyncerHandler{
		client: client,
		cache:  cache,
	}
}

// ClearRecords implements databroker.SyncerHandler.
func (mgr *sessionBindingSyncerHandler) ClearRecords(ctx context.Context) {
	// TODO
}

// GetDataBrokerServiceClient implements databroker.SyncerHandler.
func (mgr *sessionBindingSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.client
}

func (mgr *sessionBindingSyncerHandler) fetchRelatedRecords(ctx context.Context, binding *session.SessionBinding) []*databroker.Record {
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

// TODO : this logic probably needs work. For example if there are somehow out of date records in this list.
func (mgr *sessionBindingSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	log.Warn().Uint64("serverVersion", serverVersion).Int("numRecords", len(records)).Msg("syncing session bindings")
	for _, record := range records {
		sessionID := SessionID(record.Id)
		if record.DeletedAt != nil {
			slog.Warn("revoking session meta")
			mgr.cache.RevokeSessionMeta(sessionID)
			mgr.cache.InvalidatePreviousCodes(sessionID)
			mgr.cache.InvalidateIfOlder(sessionID, record.Version)
			continue
		}
		var binding session.SessionBinding
		if err := record.GetData().UnmarshalTo(&binding); err != nil {
			panic(err)
		}
		recordsToInvalidate := mgr.fetchRelatedRecords(ctx, &binding)
		mgr.cache.PutSession(sessionID, recordsToInvalidate)
		mgr.cache.PutSessionMeta(sessionID, &binding)
	}
}

type identitySyncer struct {
	client databroker.DataBrokerServiceClient
}

var _ databroker.SyncerHandler = (*identitySyncer)(nil)

func (mgr *identitySyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.client
}

func (mgr *identitySyncer) ClearRecords(ctx context.Context) {
	panic("not implemented")
}

func (mgr *identitySyncer) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	panic("not implemented")
}
