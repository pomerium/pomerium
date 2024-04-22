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
	ctx context.Context
	mgr *Manager
}

func newSessionSyncer(ctx context.Context, mgr *Manager) *databroker.Syncer {
	return databroker.NewSyncer("identity_manager/sessions", sessionSyncerHandler{ctx: ctx, mgr: mgr},
		databroker.WithTypeURL(grpcutil.GetTypeURL(new(session.Session))))
}

func (h sessionSyncerHandler) ClearRecords(_ context.Context) {
	h.mgr.onDeleteAllSessions(h.ctx)
}

func (h sessionSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return h.mgr.cfg.Load().dataBrokerClient
}

func (h sessionSyncerHandler) UpdateRecords(_ context.Context, _ uint64, records []*databroker.Record) {
	for _, record := range records {
		if record.GetDeletedAt() != nil {
			h.mgr.onDeleteSession(h.ctx, record.GetId())
		} else {
			var s session.Session
			err := record.Data.UnmarshalTo(&s)
			if err != nil {
				log.Ctx(h.ctx).Warn().Err(err).Msg("invalid data in session record, ignoring")
			} else {
				h.mgr.onUpdateSession(h.ctx, &s)
			}
		}
	}
}

type userSyncerHandler struct {
	ctx context.Context
	mgr *Manager
}

func newUserSyncer(ctx context.Context, mgr *Manager) *databroker.Syncer {
	return databroker.NewSyncer("identity_manager/users", userSyncerHandler{ctx: ctx, mgr: mgr},
		databroker.WithTypeURL(grpcutil.GetTypeURL(new(user.User))))
}

func (h userSyncerHandler) ClearRecords(_ context.Context) {
	h.mgr.onDeleteAllUsers(h.ctx)
}

func (h userSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return h.mgr.cfg.Load().dataBrokerClient
}

func (h userSyncerHandler) UpdateRecords(_ context.Context, _ uint64, records []*databroker.Record) {
	for _, record := range records {
		if record.GetDeletedAt() != nil {
			h.mgr.onDeleteUser(h.ctx, record.GetId())
		} else {
			var u user.User
			err := record.Data.UnmarshalTo(&u)
			if err != nil {
				log.Ctx(h.ctx).Warn().Err(err).Msg("invalid data in user record, ignoring")
			} else {
				h.mgr.onUpdateUser(h.ctx, &u)
			}
		}
	}
}
