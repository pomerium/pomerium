package pending

import (
	"context"
	"log/slog"
	"sync"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type sbrSyncerHandler struct {
	client databroker.DataBrokerServiceClient
	wg     sync.WaitGroup

	seenVersionMu *sync.RWMutex
	cache         *sessionCache
}

func newSbrSyncerHandler(cache *sessionCache, client databroker.DataBrokerServiceClient) *sbrSyncerHandler {
	return &sbrSyncerHandler{
		cache:         cache,
		client:        client,
		seenVersionMu: &sync.RWMutex{},
	}
}

func (mgr *sbrSyncerHandler) WaitForSync() {
	mgr.wg.Wait()
}

// ClearRecords implements databroker.SyncerHandler.
func (mgr *sbrSyncerHandler) ClearRecords(ctx context.Context) {
	// TODO
}

// GetDataBrokerServiceClient implements databroker.SyncerHandler.
func (mgr *sbrSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.client
}

func (mgr *sbrSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	for _, record := range records {
		var sbr session.SessionBindingRequest
		if err := record.GetData().UnmarshalTo(&sbr); err != nil {
			panic(err)
		}
		slog.With("code", sbr.Key, "deletedAt", record.GetDeletedAt()).Warn("saw an update from a session binding request")
		mgr.cache.PutCode(SessionID(sbr.Key), &CodeRequest{
			Code:      CodeID(record.GetId()),
			DeletedAt: record.GetDeletedAt(),
			Req:       &sbr,
		})
	}
}
