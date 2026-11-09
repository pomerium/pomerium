package idpsession

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	metrics_ids "github.com/pomerium/pomerium/pkg/metrics"
	"github.com/pomerium/pomerium/pkg/storage"
)

type RefreshConfig struct {
	SessionRefreshGracePeriod         time.Duration
	SessionRefreshCoolOffDuration     time.Duration
	RefreshSessionAtIDTokenExpiration RefreshSessionAtIDTokenExpiration
	UpdateUserInfoInterval            time.Duration
	Now                               func() time.Time
	EventMgr                          *events.Manager
	TracerProvider                    oteltrace.TracerProvider
}

type refreshManager struct {
	refreshMu sync.Mutex

	refreshBySID map[string]*refreshIDPSessionScheduler

	// idpsession id -> scheduler. Each sign-on holds its own tokens, so each
	// one is refreshed on its own schedule.
	refreshSessionSchedulers map[string]*refreshIDPSessionScheduler
	// user id -> scheduler. Userinfo belongs to the user, not to a sign-on, so
	// a user with several sign-ons is still only refreshed once.
	userInfoSchedulers map[string]*updateUserInfoScheduler
	// idpsession id -> user id, so a deleted session can find its user.
	sessionUsers map[string]string
	sessionSIDs  map[string]string

	cfg              atomic.Pointer[RefreshConfig]
	idx              IdentityIndex
	clientB          databroker.ClientGetter
	getAuthenticator func(ctx context.Context, idpID string) (identity.Authenticator, error)
}

func newRefreshManager(
	cfg RefreshConfig,
	// store idpSessionGetter,
	idx IdentityIndex,
	clientB databroker.ClientGetter,
	getAuthenticator func(ctx context.Context, idpID string) (identity.Authenticator, error),
) *refreshManager {
	mgr := &refreshManager{
		refreshBySID:             map[string]*refreshIDPSessionScheduler{},
		refreshSessionSchedulers: map[string]*refreshIDPSessionScheduler{},
		userInfoSchedulers:       map[string]*updateUserInfoScheduler{},
		sessionUsers:             map[string]string{},
		sessionSIDs:              map[string]string{},
		cfg:                      atomic.Pointer[RefreshConfig]{},
		// store:                    store,
		idx:              idx,
		clientB:          clientB,
		getAuthenticator: getAuthenticator,
	}
	mgr.cfg.Store(&cfg)
	return mgr
}

func (mgr *refreshManager) updateConfig(ctx context.Context, cfg RefreshConfig) {
	log.Ctx(ctx).Info().Msg("updated identity manager refresh config")
	mgr.cfg.Store(&cfg)
}

func (mgr *refreshManager) Close() {
	mgr.refreshMu.Lock()
	defer mgr.refreshMu.Unlock()

	for _, uiss := range mgr.userInfoSchedulers {
		uiss.Stop()
	}
	mgr.userInfoSchedulers = map[string]*updateUserInfoScheduler{}

	for _, rss := range mgr.refreshSessionSchedulers {
		rss.Stop()
	}
	for _, rss := range mgr.refreshBySID {
		rss.Stop()
	}
	mgr.refreshBySID = map[string]*refreshIDPSessionScheduler{}
	mgr.refreshSessionSchedulers = map[string]*refreshIDPSessionScheduler{}
	mgr.sessionUsers = map[string]string{}
	mgr.sessionSIDs = map[string]string{}
}

func (mgr *refreshManager) onUpdateIDPSession(ctx context.Context, s *idpsession.IDPSession) {
	log.Ctx(ctx).Debug().Str("idp-session-id", s.GetId()).Msg("idpsession updated")

	mgr.refreshMu.Lock()
	defer mgr.refreshMu.Unlock()

	mgr.sessionUsers[s.GetId()] = s.GetUserId()
	mgr.updateRefreshSchedulerLocked(ctx, s)

	if _, ok := mgr.userInfoSchedulers[s.GetUserId()]; !ok {
		mgr.userInfoSchedulers[s.GetUserId()] = newUpdateUserInfoScheduler(
			ctx,
			mgr.cfg.Load().UpdateUserInfoInterval,
			mgr.updateUserInfo,
			s.GetUserId(),
		)
	}
}

func (mgr *refreshManager) updateRefreshSchedulerLocked(ctx context.Context, s *idpsession.IDPSession) {
	id := s.GetId()
	previousSID := mgr.sessionSIDs[id]
	// sid changed
	if previousSID != "" && previousSID != s.GetSid() {
		mgr.stopSIDRefreshIfUnusedLocked(previousSID, id)
	}

	// no sid, refresh independently
	if s.GetSid() == "" {
		delete(mgr.sessionSIDs, id)
		rss, ok := mgr.refreshSessionSchedulers[id]
		if !ok {
			rss = mgr.newRefreshScheduler(ctx, mgr.refreshOne, id)
			mgr.refreshSessionSchedulers[id] = rss
		}
		rss.Update(s)
		return
	}

	// has sid, delete standalone refresh scheduler for "" -> <sid> case
	if rss, ok := mgr.refreshSessionSchedulers[id]; ok {
		rss.Stop()
		delete(mgr.refreshSessionSchedulers, id)
	}

	// same sid, update scheduler.
	mgr.sessionSIDs[id] = s.GetSid()
	rss, ok := mgr.refreshBySID[s.GetSid()]
	if !ok {
		rss = mgr.newRefreshScheduler(ctx, mgr.refreshSID, s.GetSid())
		mgr.refreshBySID[s.GetSid()] = rss
	}
	rss.Update(s)
}

func (mgr *refreshManager) newRefreshScheduler(
	ctx context.Context,
	refresh func(context.Context, string),
	key string,
) *refreshIDPSessionScheduler {
	cfg := mgr.cfg.Load()
	return newRefreshSessionScheduler(
		ctx,
		cfg.Now,
		cfg.SessionRefreshGracePeriod,
		cfg.SessionRefreshCoolOffDuration,
		cfg.RefreshSessionAtIDTokenExpiration,
		refresh,
		key,
	)
}

func (mgr *refreshManager) stopSIDRefreshIfUnusedLocked(sid, excludingID string) {
	for _, session := range mgr.idx.IDPSessionsBySID(sid) {
		if session.GetId() != excludingID {
			return
		}
	}
	if rss, ok := mgr.refreshBySID[sid]; ok {
		rss.Stop()
		delete(mgr.refreshBySID, sid)
	}
}

func (mgr *refreshManager) cleanupIDPSession(
	ctx context.Context,
	id string,
) {
	l := log.Ctx(ctx).With().Str("idpsession-id", id).Logger()
	if _, err := storage.DeleteDataBrokerRecord(
		ctx, mgr.clientB.GetDataBrokerServiceClient(), idpSessionTypeURL, id,
	); err != nil {
		l.Err(err).Msg("failed to delete idpsession")
		return
	}
}

// cleanUpSchedulers  clears the refresh session schedulers, and userinfo scheduler if
// no more sessions exist for the user.
func (mgr *refreshManager) cleanUpSchedulers(id string) {
	mgr.refreshMu.Lock()
	defer mgr.refreshMu.Unlock()

	if rss, ok := mgr.refreshSessionSchedulers[id]; ok {
		rss.Stop()
		delete(mgr.refreshSessionSchedulers, id)
	}
	if sid := mgr.sessionSIDs[id]; sid != "" {
		mgr.stopSIDRefreshIfUnusedLocked(sid, id)
		delete(mgr.sessionSIDs, id)
	}
	userID, ok := mgr.sessionUsers[id]
	if !ok {
		return
	}
	delete(mgr.sessionUsers, id)

	if len(mgr.idx.IDPSessionsByUser(userID)) > 0 {
		return
	}
	if uiss, ok := mgr.userInfoSchedulers[userID]; ok {
		uiss.Stop()
		delete(mgr.userInfoSchedulers, userID)
	}
}

func (mgr *refreshManager) updateUserInfo(ctx context.Context, userID string) {
	log.Ctx(ctx).Info().Str("user-id", userID).Msg("updating user info")

	idpSessByUser := mgr.idx.IDPSessionsByUser(userID)
	if len(idpSessByUser) == 0 {
		log.Ctx(ctx).Error().
			Str("user-id", userID).
			Msg("no idpsession found for update")
		return
	}

	l := log.Ctx(ctx).With().Str("user-id", userID).Logger()

	u := mgr.idx.GetUser(userID)
	if u == nil {
		l.Error().Msg("no user found for update")
		return
	}

	// update user info with each token independently
	updated := 0
	for _, idpSess := range idpSessByUser {
		authenticator, err := mgr.getAuthenticator(ctx, idpSess.GetIdpId())
		if err != nil {
			l.Err(err).Str("idpsession-id", idpSess.GetId()).Msg("no authenticator configured")
			mgr.cleanupIDPSession(ctx, idpSess.GetId())
			continue
		}

		err = authenticator.UpdateUserInfo(
			ctx,
			idpsession.FromOAuthToken(idpSess),
			manager.NewMultiUnmarshaler(manager.NewUserUnmarshaler(u), idpSess),
		)
		metrics.RecordIdentityManagerUserRefresh(ctx, err)
		mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
		if oidc.IsTemporaryError(err) {
			l.Err(err).Str("idpsession-id", idpSess.GetId()).Msg("failed to update user info")
			continue
		} else if err != nil {
			l.Err(err).Str("idpsession-id", idpSess.GetId()).Msg("failed to update user info, revoking session")
			mgr.cleanupIDPSession(ctx, idpSess.GetId())
			continue
		}
		updated++

		if err := mgr.patchIDPSessionUserClaims(ctx, idpSess); err != nil {
			l.Err(err).Msg("failed to patch idpsession list")
		}
	}

	if updated == 0 {
		return
	}

	if err := mgr.patchUserInfo(ctx, u); err != nil {
		l.Err(err).Msg("failed to patch user info")
	}
}

func (mgr *refreshManager) patchUserInfo(ctx context.Context, u *user.User) error {
	log.Ctx(ctx).Debug().
		Str("user-id", u.GetId()).Msg("updating user record userinfo")

	fm, err := fieldmaskpb.New(u, "claims", "name", "email")
	if err != nil {
		return fmt.Errorf("failed to create fieldmask for user")
	}
	_, err = mgr.clientB.GetDataBrokerServiceClient().Patch(ctx, &databroker.PatchRequest{
		Records:   []*databroker.Record{databroker.NewRecord(u)},
		FieldMask: fm,
	})
	if err != nil {
		return fmt.Errorf("failed to patch updated user record : %w", err)
	}
	return nil
}

func (mgr *refreshManager) patchIDPSessionUserClaims(
	ctx context.Context,
	idpSess *idpsession.IDPSession,
) error {
	sFm, err := fieldmaskpb.New(new(idpsession.IDPSession), "claims")
	if err != nil {
		return fmt.Errorf("failed to create field mask for idpsession")
	}

	if _, err := mgr.clientB.GetDataBrokerServiceClient().Patch(ctx, &databroker.PatchRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(idpSess),
		},
		FieldMask: sFm,
	}); err != nil {
		return fmt.Errorf("failed to patch updated idpsession record: %w", err)
	}
	return nil
}

func (mgr *refreshManager) refreshOne(ctx context.Context, id string) {
	log.Ctx(ctx).Debug().
		Str("idpsession-id", id).
		Msg("refreshing session")

	s, ok := mgr.idx.IDPSession(id)
	if !ok {
		log.Ctx(ctx).Info().
			Str("idpsession-id", id).
			Msg("no session found for refresh")
		mgr.cleanUpSchedulers(id)
		return
	}
	l := log.Ctx(ctx).With().Str("idpsession-id", id).Str("user-id", s.GetUserId()).Logger()

	authenticator, err := mgr.getAuthenticator(ctx, s.GetIdpId())
	if err != nil {
		l.Info().Err(err).Msg("no authenticator defined deleting session")
		mgr.cleanupIDPSession(ctx, id)
		return
	}

	if s.GetOauthToken() == nil {
		log.Ctx(ctx).Error().Str("user-id", s.GetUserId()).Str("idpsession-id", id).
			Msg("no session oauth2 token found for refresh")
		return
	}

	newToken, err := authenticator.Refresh(ctx, idpsession.FromOAuthToken(s), s)
	metrics.RecordIdentityManagerSessionRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
	if oidc.IsTemporaryError(err) {
		l.Err(err).Msg("failed to refresh oauth2 token")
		return
	} else if err != nil {
		l.Err(err).Msg("failed to refresh oauth2 token, deleting session")
		mgr.cleanupIDPSession(ctx, id)
		return
	}
	idpsession.UpdateOAuthToken(newToken, s)

	u := mgr.idx.GetUser(s.GetUserId())
	if u == nil {
		u = &user.User{
			Id: s.GetUserId(),
		}
	}
	dst := manager.NewMultiUnmarshaler(manager.NewUserUnmarshaler(u), s)
	err = authenticator.UpdateUserInfo(ctx, idpsession.FromOAuthToken(s), dst)
	metrics.RecordIdentityManagerUserRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
	if oidc.IsTemporaryError(err) {
		l.Err(err).Msg("failed to update user info")
	} else if err != nil {
		l.Err(err).Msg("failed to update user info, revoking session")
		mgr.cleanupIDPSession(ctx, s.GetId())
		return
	} else if err := mgr.patchUserInfo(ctx, u); err != nil {
		l.Err(err).Msg("failed to patch user info")
	}
	if err := mgr.patchIdpSessionList(ctx, []*idpsession.IDPSession{s}, s); err != nil {
		l.Err(err).Msg("failed to persist idpsession updates")
	}
}

func (mgr *refreshManager) refreshSID(ctx context.Context, sid string) {
	idpSessList := mgr.idx.IDPSessionsBySID(sid)
	if len(idpSessList) == 0 {
		return
	}
	var toRefresh *idpsession.IDPSession
	for _, idpSess := range idpSessList {
		if idpSess.GetOauthToken() != nil {
			toRefresh = idpSess
			break
		}
	}
	if toRefresh == nil {
		log.Ctx(ctx).Error().Str("sid", sid).Int("num-idpsessions", len(idpSessList)).Msg("no session oauth2 token found for refresh")
		return
	}

	l := log.Ctx(ctx).With().Str("sid", sid).Str("idpsession-id", toRefresh.GetId()).Logger()
	authenticator, err := mgr.getAuthenticator(ctx, toRefresh.GetIdpId())
	if err != nil {
		l.Info().Err(err).Msg("no authenticator defined deleting sessions")
		for _, session := range idpSessList {
			mgr.cleanupIDPSession(ctx, session.GetId())
		}
		return
	}

	newToken, err := authenticator.Refresh(ctx, idpsession.FromOAuthToken(toRefresh), toRefresh)
	metrics.RecordIdentityManagerSessionRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
	if oidc.IsTemporaryError(err) {
		l.Err(err).Msg("failed to refresh oauth2 token")
		return
	} else if err != nil {
		l.Err(err).Msg("failed to refresh oauth2 token, deleting sessions")
		for _, session := range idpSessList {
			mgr.cleanupIDPSession(ctx, session.GetId())
		}
		return
	}

	idpsession.UpdateOAuthToken(newToken, toRefresh)

	u := mgr.idx.GetUser(toRefresh.GetUserId())
	if u == nil {
		u = &user.User{
			Id: toRefresh.GetUserId(),
		}
	}
	dst := manager.NewMultiUnmarshaler(manager.NewUserUnmarshaler(u), toRefresh)
	err = authenticator.UpdateUserInfo(ctx, idpsession.FromOAuthToken(toRefresh), dst)
	metrics.RecordIdentityManagerUserRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
	if oidc.IsTemporaryError(err) {
		l.Err(err).Msg("failed to update user info")
	} else if err != nil {
		l.Err(err).Msg("failed to update user info, revoking sessions")
		for _, session := range idpSessList {
			mgr.cleanupIDPSession(ctx, session.GetId())
		}
		return
	} else if err := mgr.patchUserInfo(ctx, u); err != nil {
		l.Err(err).Msg("failed to patch user info")
	}
	if err := mgr.patchIdpSessionList(ctx, idpSessList, toRefresh); err != nil {
		l.Err(err).Msg("failed to persist idpsession updates")
	}
}

func (mgr *refreshManager) patchIdpSessionList(
	ctx context.Context,
	sessions []*idpsession.IDPSession,
	refreshed *idpsession.IDPSession,
) error {
	log.Ctx(ctx).Debug().
		Int("idpsession-count", len(sessions)).
		Msg("updating idpsession tokens")
	records := make([]*databroker.Record, 0, len(sessions))
	for _, session := range sessions {
		patch := &idpsession.IDPSession{
			Id:         session.GetId(),
			RawIdToken: refreshed.GetRawIdToken(),
			IdToken:    proto.CloneOf(refreshed.GetIdToken()),
			OauthToken: proto.CloneOf(refreshed.GetOauthToken()),
			Claims:     proto.CloneOf(refreshed.GetClaims()),
		}
		records = append(records, databroker.NewRecord(patch))
	}
	if _, err := mgr.clientB.GetDataBrokerServiceClient().Patch(ctx, &databroker.PatchRequest{
		Records:   records,
		FieldMask: &fieldmaskpb.FieldMask{Paths: []string{"raw_id_token", "id_token", "oauth_token", "claims"}},
	}); err != nil {
		return fmt.Errorf("failed to update idpsession tokens : %w", err)
	}
	return nil
}

func (mgr *refreshManager) recordLastError(id string, err error) {
	if err == nil {
		return
	}
	evtMgr := mgr.cfg.Load().EventMgr
	if evtMgr == nil {
		return
	}
	evtMgr.Dispatch(&events.LastError{
		Time:    timestamppb.Now(),
		Message: err.Error(),
		Id:      id,
	})
}
