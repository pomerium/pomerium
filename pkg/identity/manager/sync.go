package manager

import (
	"context"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type sessionSyncerHandler struct {
	baseCtx context.Context
	mgr     *Manager
}

func newSessionSyncer(ctx context.Context, mgr *Manager) *databroker.Syncer {
	return databroker.NewSyncer(ctx, "identity_manager/sessions", sessionSyncerHandler{baseCtx: ctx, mgr: mgr},
		databroker.WithTypeURL(grpcutil.GetTypeURL(new(session.Session))))
}

func (h sessionSyncerHandler) ClearRecords(ctx context.Context) {
	h.mgr.onDeleteAllSessions(ctx)
}

func (h sessionSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return h.mgr.cfg.Load().dataBrokerClient
}

func (h sessionSyncerHandler) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	for _, record := range records {
		if record.GetDeletedAt() != nil {
			h.mgr.onDeleteSession(h.baseCtx, record.GetId())
		} else {
			var s session.Session
			err := record.Data.UnmarshalTo(&s)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("invalid data in session record, ignoring")
			} else {
				h.mgr.onUpdateSession(h.baseCtx, &s)
			}
		}
	}
}

type userSyncerHandler struct {
	baseCtx context.Context
	mgr     *Manager
}

func newUserSyncer(ctx context.Context, mgr *Manager) *databroker.Syncer {
	return databroker.NewSyncer(ctx, "identity_manager/users", userSyncerHandler{baseCtx: ctx, mgr: mgr},
		databroker.WithTypeURL(grpcutil.GetTypeURL(new(user.User))))
}

func (h userSyncerHandler) ClearRecords(ctx context.Context) {
	h.mgr.onDeleteAllUsers(ctx)
}

func (h userSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return h.mgr.cfg.Load().dataBrokerClient
}

func (h userSyncerHandler) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	for _, record := range records {
		if record.GetDeletedAt() != nil {
			h.mgr.onDeleteUser(h.baseCtx, record.GetId())
		} else {
			var u user.User
			err := record.Data.UnmarshalTo(&u)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("invalid data in user record, ignoring")
			} else {
				h.mgr.onUpdateUser(h.baseCtx, &u)
			}
		}
	}
}
