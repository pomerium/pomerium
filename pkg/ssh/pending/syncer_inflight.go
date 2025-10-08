package pending

import (
	"context"
	"sync"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/rs/zerolog/log"
)

type sbrSyncerHandler struct {
	tr     *pendingSessionTracker
	client databroker.DataBrokerServiceClient
	wg     sync.WaitGroup

	seenVersionMu *sync.RWMutex
	seenVersion   uint64
	cache         *sessionCache
}

func newSbrSyncerHandler(cache *sessionCache, tr *pendingSessionTracker, client databroker.DataBrokerServiceClient) *sbrSyncerHandler {
	return &sbrSyncerHandler{
		tr:            tr,
		cache:         cache,
		client:        client,
		seenVersionMu: &sync.RWMutex{},
		seenVersion:   uint64(0),
	}
}

func (mgr *sbrSyncerHandler) WaitForSync() {
	mgr.wg.Wait()
}

// ClearRecords implements databroker.SyncerHandler.
func (mgr *sbrSyncerHandler) ClearRecords(ctx context.Context) {
	mgr.tr.mu.Lock()
	defer mgr.tr.mu.Unlock()

	for _, meta := range mgr.tr.sess {
		meta.Close()
	}
}

// GetDataBrokerServiceClient implements databroker.SyncerHandler.
func (mgr *sbrSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.client
}

func (mgr *sbrSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	mgr.seenVersionMu.Lock()
	defer mgr.seenVersionMu.Unlock()
	maxVersion := uint64(0)
	log.Warn().Uint64("serverVersion", serverVersion).Int("numRecords", len(records)).Msg("syncing session binding requests")
	for _, record := range records {
		var sbr session.SessionBindingRequest
		if err := record.GetData().UnmarshalTo(&sbr); err != nil {
			panic(err)
		}

		mgr.tr.SetBindingRequest(sbr.Key, &SessionBindingCode{
			Code:      record.GetId(),
			DeletedAt: record.DeletedAt,
			Req:       &sbr,
		})
		maxVersion = max(record.Version, maxVersion)
		mgr.cache.PutCode(SessionID(sbr.Key), CodeRequest{
			Code:      CodeID(record.GetId()),
			DeletedAt: record.GetDeletedAt(),
			Req:       &sbr,
		})
	}
	mgr.seenVersion = maxVersion

}

func (mgr *sbrSyncerHandler) getSeenVersion() uint64 {
	mgr.seenVersionMu.RLock()
	defer mgr.seenVersionMu.RUnlock()
	return mgr.seenVersion
}
