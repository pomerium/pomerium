package idpsession

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/identity"
	metrics_ids "github.com/pomerium/pomerium/pkg/metrics"
	"github.com/pomerium/pomerium/pkg/storage"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TODO : this could use some simplification
type config struct {
	// dataBrokerClient                  databroker.DataBrokerServiceClient
	sessionRefreshGracePeriod         time.Duration
	sessionRefreshCoolOffDuration     time.Duration
	refreshSessionAtIDTokenExpiration RefreshSessionAtIDTokenExpiration
	updateUserInfoInterval            time.Duration
	// leaseTTL                          time.Duration
	now              func() time.Time
	eventMgr         *events.Manager
	getAuthenticator func(ctx context.Context, idpID string) (identity.Authenticator, error)
	tracerProvider   oteltrace.TracerProvider
}

type refreshManager struct {
	refreshMu sync.Mutex

	refreshSessionSchedulers map[string]*refreshIDPSessionScheduler
	userInfoSchedulers       map[string]*updateUserInfoScheduler
	cfg                      atomic.Pointer[config]
	dataStore                *dataStore

	clientB databroker.ClientGetter
}

func newRefreshManager(
	cfg config,
	dataStore *dataStore,
	clientB databroker.ClientGetter,
) *refreshManager {
	mgr := &refreshManager{
		refreshSessionSchedulers: map[string]*refreshIDPSessionScheduler{},
		userInfoSchedulers:       map[string]*updateUserInfoScheduler{},
		cfg:                      atomic.Pointer[config]{},
		dataStore:                dataStore,
		clientB:                  clientB,
	}
	mgr.cfg.Store(&cfg)
	return mgr
}

func (mgr *refreshManager) updateConfig(ctx context.Context, cfg config) {
	// TODO :
	panic("implement me")
}

func (mgr *refreshManager) onUpdateIDPSession(ctx context.Context, s *idpsession.IDPSession) {
	log.Ctx(ctx).Debug().Str("idp-session-id", s.GetId()).Msg("idpsession updated")

	mgr.refreshMu.Lock()
	rss, rOk := mgr.refreshSessionSchedulers[s.GetId()]
	if !rOk {
		rss = newRefreshSessionScheduler(
			ctx,
			mgr.cfg.Load().now,
			mgr.cfg.Load().sessionRefreshGracePeriod,
			mgr.cfg.Load().sessionRefreshCoolOffDuration,
			mgr.cfg.Load().refreshSessionAtIDTokenExpiration,
			mgr.refresh,
			s.GetId(),
		)
		mgr.refreshSessionSchedulers[s.GetId()] = rss
	}
	rss.Update(s)

	uuis, uOk := mgr.userInfoSchedulers[s.GetId()]
	if !uOk {
		uuis = newUpdateUserInfoScheduler(
			ctx,
			mgr.cfg.Load().updateUserInfoInterval,
			mgr.updateUserInfo,
			s.GetId(),
		)
		mgr.userInfoSchedulers[s.GetId()] = uuis
	}
	mgr.refreshMu.Unlock()
}

func (mgr *refreshManager) deleteIDPSession(ctx context.Context, id string) {
	log.Ctx(ctx).Debug().
		Str("idpsession-id", id).
		Msg("deleting idpsession")
	mgr.dataStore.deleteIDPSession(id)
	_, err := storage.DeleteDataBrokerRecord(
		ctx, mgr.clientB.GetDataBrokerServiceClient(), "type.googleapis.com/idpsession.IDPSession", id,
	)
	if err != nil {
		log.Ctx(ctx).Err(err).Str("idpsession-id", id).Msg("failed to delete session, a future reconcile will pick this up")
	}
}

func (mgr *refreshManager) updateToken(ctx context.Context, s *idpsession.IDPSession) error {
	log.Ctx(ctx).Debug().
		Str("user-id", s.GetUserId()).
		Str("idpsession-id", s.GetId()).
		Msg("updating idpsession tokens and userinfo")

	fm, err := fieldmaskpb.New(s, "oauth_token", "id_token", "claims")
	if err != nil {
		return fmt.Errorf("failed to create fieldmask for idpsession")
	}
	// TODO : consider in-memory patch here for racing schedulers. or use singleflight for refresh / userinfo callbacks.
	mgr.dataStore.putIDPSession(s)
	_, err = mgr.clientB.GetDataBrokerServiceClient().Patch(ctx, &databroker.PatchRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(proto.CloneOf(s)),
		},
		FieldMask: fm,
	})

	if err != nil {
		return fmt.Errorf("failed to patch updated idpsession record : %w", err)
	}
	return nil
}

func (mgr *refreshManager) updateUserInfo(ctx context.Context, id string) {
	log.Ctx(ctx).Info().Str("idpsession-id", id).Msg("updating user info")

	u := mgr.dataStore.getIDPSession(id)
	if u == nil {
		log.Ctx(ctx).Error().
			Str("idpsession-id", id).
			Msg("no user found for update")
		return
	}

	l := log.Ctx(ctx).With().Str("idpsession-id", id).Str("user-id", u.UserId).Logger()
	authenticator, err := mgr.cfg.Load().getAuthenticator(ctx, id)
	if err != nil {
		l.Err(err).Msg("no authenticator configured")
		mgr.deleteIDPSession(ctx, id)
		return
	}

	err = authenticator.UpdateUserInfo(ctx, FromOAuthToken(u), u)
	metrics.RecordIdentityManagerUserRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
	if isTemporaryError(err) {
		l.Err(err).Msg("failed to update user info")
		return
	} else if err != nil {
		l.Err(err).Msg("failed to update user info, deleting session")
		mgr.deleteIDPSession(ctx, id)
		return
	}
	if err := mgr.patchUserInfo(ctx, u); err != nil {
		l.Err(err).Msg("failed to patch user info")
	}
}

func (mgr *refreshManager) patchUserInfo(ctx context.Context, u *idpsession.IDPSession) error {
	log.Ctx(ctx).Debug().
		Str("idpsession-id", u.GetId()).
		Str("user-id", u.GetUserId()).Msg("updating idpsession userinfo")

	fm, err := fieldmaskpb.New(u, "claims")
	if err != nil {
		return fmt.Errorf("failed to create fieldmask for idpsession")
	}
	// TODO : consider in-memory patch here for racing schedulers. or use singleflight for refresh / userinfo callbacks.
	mgr.dataStore.putIDPSession(u)
	_, err = mgr.clientB.GetDataBrokerServiceClient().Patch(ctx, &databroker.PatchRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(proto.CloneOf(u)),
		},
		FieldMask: fm,
	})

	if err != nil {
		return fmt.Errorf("failed to patch updated idpsession record : %w", err)
	}
	return nil
}

func (mgr *refreshManager) refresh(ctx context.Context, id string) {
	log.Ctx(ctx).Debug().
		Str("idpsession-id", id).
		Msg("refreshing session")

	s := mgr.dataStore.getIDPSession(id)

	if s == nil {
		log.Ctx(ctx).Info().
			Str("idpsession-id", id).
			Msg("no session found for refresh")
		return
	}
	l := log.Ctx(ctx).With().Str("idpsession-id", id).Str("user-id", s.GetUserId()).Logger()

	authenticator, err := mgr.cfg.Load().getAuthenticator(ctx, s.GetIdpId())
	if err != nil {
		l.Info().Err(err).Msg("no authenticator defined deleting session")
		mgr.deleteIDPSession(ctx, id)
		return
	}

	if s.GetOauthToken() == nil {
		l.Info().Msg("no session oauth2 token found for refresh")
		return
	}

	newToken, err := authenticator.Refresh(ctx, FromOAuthToken(s), s)
	metrics.RecordIdentityManagerSessionRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
	if isTemporaryError(err) {
		l.Err(err).Msg("failed to refresh oauth2 token")
		return
	} else if err != nil {
		l.Err(err).Msg("failed to refresh oauth2 token, deleting session")
		// TODO : this should probably stay delete
		mgr.deleteIDPSession(ctx, id)
		return
	}
	UpdateOAuthToken(newToken, s)
	err = authenticator.UpdateUserInfo(ctx, FromOAuthToken(s), s)
	metrics.RecordIdentityManagerUserRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
	if isTemporaryError(err) {
		l.Err(err).Msg("failed to update user info")
		return
	} else if err != nil {
		l.Err(err).Msg("failed to update user info, deleting idpsession")
		// TODO : this should probably stay delete
		mgr.deleteIDPSession(ctx, id)
		return
	}
	if err := mgr.updateToken(ctx, s); err != nil {
		log.Ctx(ctx).Err(err).Msg("failed to persist idpsession updates")
	}
}

func (mgr *refreshManager) recordLastError(id string, err error) {
	if err == nil {
		return
	}
	evtMgr := mgr.cfg.Load().eventMgr
	if evtMgr == nil {
		return
	}
	evtMgr.Dispatch(&events.LastError{
		Time:    timestamppb.Now(),
		Message: err.Error(),
		Id:      id,
	})
}
