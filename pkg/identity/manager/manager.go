// Package manager contains an identity manager responsible for refreshing sessions and creating users.
package manager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/identity/idpsession"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/identity/identity"
	metrics_ids "github.com/pomerium/pomerium/pkg/metrics"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Authenticator is an identity.Provider with only the methods needed by the manager.
type Authenticator interface {
	Refresh(context.Context, *oauth2.Token, identity.State) (*oauth2.Token, error)
	Revoke(context.Context, *oauth2.Token) error
	UpdateUserInfo(context.Context, *oauth2.Token, any) error
}

// A Manager refreshes identity information using session and user data.
type Manager struct {
	cfg atomic.Pointer[config]

	mu                       sync.Mutex
	dataStore                *dataStore
	refreshSessionSchedulers map[string]*refreshSessionScheduler
	updateUserInfoSchedulers map[string]*updateUserInfoScheduler
}

// New creates a new identity manager.
func New(
	options ...Option,
) *Manager {
	mgr := &Manager{
		dataStore:                newDataStore(),
		refreshSessionSchedulers: make(map[string]*refreshSessionScheduler),
		updateUserInfoSchedulers: make(map[string]*updateUserInfoScheduler),
	}
	mgr.UpdateConfig(options...)
	return mgr
}

// UpdateConfig updates the manager with the new options.
func (mgr *Manager) UpdateConfig(options ...Option) {
	mgr.cfg.Store(newConfig(options...))
}

// GetDataBrokerServiceClient gets the databroker client.
func (mgr *Manager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.cfg.Load().dataBrokerClient
}

// Run runs the manager. This method blocks until an error occurs or the given context is canceled.
func (mgr *Manager) Run(ctx context.Context) error {
	leaser := databrokerutil.NewLeaser("identity_manager", mgr.cfg.Load().leaseTTL, mgr)
	return leaser.Run(ctx)
}

// RunLeased runs the identity manager when a lease is acquired.
func (mgr *Manager) RunLeased(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "identity_manager")
	})
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		sessionSyncer := newSessionSyncer(ctx, mgr)
		defer sessionSyncer.Close()
		return fmt.Errorf("session syncer error: %w", sessionSyncer.Run(ctx))
	})
	eg.Go(func() error {
		userSyncer := newUserSyncer(ctx, mgr)
		defer userSyncer.Close()
		return fmt.Errorf("user syncer error: %w", userSyncer.Run(ctx))
	})
	return eg.Wait()
}

func (mgr *Manager) onDeleteAllSessions(ctx context.Context) {
	log.Ctx(ctx).Debug().Msg("all sessions deleted")

	mgr.mu.Lock()
	mgr.dataStore.deleteAllSessions()
	for sID, rss := range mgr.refreshSessionSchedulers {
		rss.Stop()
		delete(mgr.refreshSessionSchedulers, sID)
	}
	mgr.mu.Unlock()
}

func (mgr *Manager) onDeleteAllUsers(ctx context.Context) {
	log.Ctx(ctx).Debug().Msg("all users deleted")

	mgr.mu.Lock()
	mgr.dataStore.deleteAllUsers()
	for uID, uuis := range mgr.updateUserInfoSchedulers {
		uuis.Stop()
		delete(mgr.updateUserInfoSchedulers, uID)
	}
	mgr.mu.Unlock()
}

func (mgr *Manager) onDeleteSession(ctx context.Context, sessionID string) {
	log.Ctx(ctx).Debug().Str("session-id", sessionID).Msg("session deleted")

	mgr.mu.Lock()
	mgr.dataStore.deleteSession(sessionID)
	if rss, ok := mgr.refreshSessionSchedulers[sessionID]; ok {
		rss.Stop()
		delete(mgr.refreshSessionSchedulers, sessionID)
	}
	mgr.mu.Unlock()
}

func (mgr *Manager) onDeleteUser(ctx context.Context, userID string) {
	log.Ctx(ctx).Debug().Str("user-id", userID).Msg("user deleted")

	mgr.mu.Lock()
	mgr.dataStore.deleteUser(userID)
	if uuis, ok := mgr.updateUserInfoSchedulers[userID]; ok {
		uuis.Stop()
		delete(mgr.updateUserInfoSchedulers, userID)
	}
	mgr.mu.Unlock()
}

func (mgr *Manager) onUpdateSession(ctx context.Context, s *session.Session) {
	log.Ctx(ctx).Debug().Str("session-id", s.GetId()).Msg("session updated")

	mgr.mu.Lock()
	mgr.dataStore.putSession(s)
	rss, ok := mgr.refreshSessionSchedulers[s.GetId()]
	if !ok {
		rss = newRefreshSessionScheduler(
			ctx,
			mgr.cfg.Load().now,
			mgr.cfg.Load().sessionRefreshGracePeriod,
			mgr.cfg.Load().sessionRefreshCoolOffDuration,
			mgr.cfg.Load().refreshSessionAtIDTokenExpiration,
			mgr.refreshSession,
			s.GetId(),
		)
		mgr.refreshSessionSchedulers[s.GetId()] = rss
	}
	rss.Update(s)
	mgr.mu.Unlock()
}

func (mgr *Manager) onUpdateUser(ctx context.Context, u *user.User) {
	log.Ctx(ctx).Debug().Str("user-id", u.GetId()).Msg("user updated")

	mgr.mu.Lock()
	mgr.dataStore.putUser(u)
	_, ok := mgr.updateUserInfoSchedulers[u.GetId()]
	if !ok {
		uuis := newUpdateUserInfoScheduler(
			ctx,
			mgr.cfg.Load().updateUserInfoInterval,
			mgr.updateUserInfo,
			u.GetId(),
		)
		mgr.updateUserInfoSchedulers[u.GetId()] = uuis
	}
	mgr.mu.Unlock()
}

func (mgr *Manager) refreshSession(ctx context.Context, sessionID string) {
	log.Ctx(ctx).Debug().
		Str("session-id", sessionID).
		Msg("refreshing session")

	mgr.mu.Lock()
	s, u := mgr.dataStore.getSessionAndUser(sessionID)
	mgr.mu.Unlock()

	if s == nil {
		log.Ctx(ctx).Info().
			Str("user-id", u.GetId()).
			Str("session-id", sessionID).
			Msg("no session found for refresh")
		return
	}

	authenticator, err := mgr.cfg.Load().getAuthenticator(ctx, s.GetIdpId())
	if err != nil {
		log.Ctx(ctx).Info().
			Err(err).
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("no authenticator defined, deleting session")
		mgr.deleteSession(ctx, sessionID)
		return
	}

	expiry := s.GetExpiresAt().AsTime()
	if !expiry.After(mgr.cfg.Load().now()) {
		log.Ctx(ctx).Info().
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("deleting expired session")
		mgr.deleteSession(ctx, sessionID)
		return
	}

	if s.GetRefreshDisabled() {
		// refresh was explicitly disabled
		return
	}

	if s.GetOauthToken() == nil {
		log.Ctx(ctx).Info().
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("no session oauth2 token found for refresh")
		return
	}

	if store := mgr.cfg.Load().idpStore; store != nil {
		// Refresh through the shared upstream IdP session, so this user's browser
		// sessions and MCP sessions collapse to one IdP call and one owner of the
		// upstream refresh token.
		if !mgr.refreshViaStore(ctx, sessionID, s, store) {
			return
		}
	} else {
		newToken, err := authenticator.Refresh(ctx, FromOAuthToken(s.OauthToken), NewSessionUnmarshaler(s))
		metrics.RecordIdentityManagerSessionRefresh(ctx, err)
		mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
		if idpsession.IsTemporary(err) {
			log.Ctx(ctx).Error().Err(err).
				Str("user-id", s.GetUserId()).
				Str("session-id", s.GetId()).
				Msg("failed to refresh oauth2 token")
			return
		} else if err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("user-id", s.GetUserId()).
				Str("session-id", s.GetId()).
				Msg("failed to refresh oauth2 token, deleting session")
			mgr.deleteSession(ctx, sessionID)
			return
		}
		s.OauthToken = ToOAuthToken(newToken)
	}

	err = authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), newMultiUnmarshaler(newUserUnmarshaler(u), NewSessionUnmarshaler(s)))
	metrics.RecordIdentityManagerUserRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
	if idpsession.IsTemporary(err) {
		log.Ctx(ctx).Error().Err(err).
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("failed to update user info")
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("failed to update user info, deleting session")
		mgr.deleteSession(ctx, sessionID)
		return
	}

	mgr.updateSession(ctx, s)
	if u != nil {
		mgr.updateUser(ctx, u)
	}
}

// refreshViaStore repopulates s from the shared upstream IdP session. It returns
// true when s was refreshed and the caller should continue (UpdateUserInfo +
// persist); false when it already handled the outcome — a transient error keeps
// the session, a dead upstream session (sign-out / revocation) deletes it.
func (mgr *Manager) refreshViaStore(ctx context.Context, sessionID string, s *session.Session, store *idpsession.Store) bool {
	// A scheduled refresh means something about this session hit its expiry, so
	// asking for a token that merely has not expired would answer the wrong
	// question. In particular the ID token can expire well before the access
	// token, and it only advances when the store actually presents: served from
	// the record, the session's ID token would stay stale, the scheduler would
	// keep computing a past-due time from it, and this would run every cool-off
	// period for the life of the session. The debounce window still collapses
	// concurrent refreshes across replicas.
	live, err := store.EnsureLive(ctx, s.GetUserId(), s.GetIdpId(), idpsession.RequireFresh())
	if errors.Is(err, idpsession.ErrNoUpstreamSession) {
		// Bootstrap during migration: seed the canonical record from this
		// session's own refresh token, then retry once. A session with no
		// refresh token can never be refreshed — delete it (matching the legacy
		// path, where authenticator.Refresh would fail permanently).
		rt := s.GetOauthToken().GetRefreshToken()
		if rt == "" {
			// Recorded like any other refresh outcome: a run of sessions deleted
			// for this reason should be visible, not silent.
			metrics.RecordIdentityManagerSessionRefresh(ctx, err)
			mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
			log.Ctx(ctx).Info().
				Str("user-id", s.GetUserId()).
				Str("session-id", sessionID).
				Msg("no upstream refresh token, deleting session")
			mgr.deleteSession(ctx, sessionID)
			return false
		}
		if serr := store.Register(ctx, s.GetUserId(), s.GetIdpId(), rt); serr != nil {
			// Every outcome of an attempted refresh is recorded, including the
			// ones that end here, or a run of seeding failures would look like no
			// refresh activity at all.
			metrics.RecordIdentityManagerSessionRefresh(ctx, serr)
			mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, serr)
			if errors.Is(serr, idpsession.ErrUpstreamSessionDead) {
				// This session's token is a copy of a grant that has already
				// died; re-seeding it would resurrect a dead upstream session.
				mgr.deleteDeadSession(ctx, sessionID, s.GetUserId(), serr)
				return false
			}
			log.Ctx(ctx).Error().Err(serr).
				Str("user-id", s.GetUserId()).
				Str("session-id", sessionID).
				Msg("failed to seed upstream idp session")
			return false
		}
		live, err = store.EnsureLive(ctx, s.GetUserId(), s.GetIdpId(), idpsession.RequireFresh())
	}
	metrics.RecordIdentityManagerSessionRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
	if errors.Is(err, idpsession.ErrUpstreamSessionDead) {
		mgr.deleteDeadSession(ctx, sessionID, s.GetUserId(), err)
		return false
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user-id", s.GetUserId()).
			Str("session-id", sessionID).
			Msg("failed to refresh upstream idp session")
		return false
	}

	s.OauthToken = ToOAuthToken(live.Token)
	// Assigned only when the provider said something about it: a new ID token, or
	// an explicit withdrawal.
	if raw, said := live.IDTokenUpdate(); said {
		s.SetRawIDToken(raw)
	}
	if len(live.Claims) > 0 {
		s.AddClaims(live.Claims)
	}
	return true
}

func (mgr *Manager) updateUserInfo(ctx context.Context, userID string) {
	log.Ctx(ctx).Info().Str("user-id", userID).Msg("updating user info")
	mgr.mu.Lock()
	u, ss := mgr.dataStore.getUserAndSessions(userID)
	mgr.mu.Unlock()

	if u == nil {
		log.Ctx(ctx).Error().
			Str("user-id", userID).
			Msg("no user found for update")
		return
	}

	for _, s := range ss {
		if s.GetOauthToken() == nil {
			log.Ctx(ctx).Error().
				Str("user-id", s.GetUserId()).
				Str("session-id", s.GetId()).
				Msg("no session oauth2 token found for updating user info")
			continue
		}

		authenticator, err := mgr.cfg.Load().getAuthenticator(ctx, s.GetIdpId())
		if err != nil {
			continue
		}

		err = authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.GetOauthToken()), newUserUnmarshaler(u))
		metrics.RecordIdentityManagerUserRefresh(ctx, err)
		mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
		if idpsession.IsTemporary(err) {
			log.Ctx(ctx).Error().Err(err).
				Str("user-id", s.GetUserId()).
				Str("session-id", s.GetId()).
				Msg("failed to update user info")
			continue
		} else if err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("user-id", s.GetUserId()).
				Str("session-id", s.GetId()).
				Msg("failed to update user info, deleting session")
			mgr.deleteSession(ctx, s.GetId())
			continue
		}

		mgr.updateUser(ctx, u)
	}
}

// deleteDeadSession deletes a session whose canonical upstream IdP session has
// permanently ended (sign-out, revocation, or an unrecoverable refresh
// outcome): re-seeding it from this session's copy would resurrect a dead
// grant, so the only remedy is a fresh login. Called from both the Register
// and EnsureLive dead-session branches of refreshViaStore.
func (mgr *Manager) deleteDeadSession(ctx context.Context, sessionID, userID string, deadErr error) {
	log.Ctx(ctx).Info().
		Str("user-id", userID).
		Str("session-id", sessionID).
		Str("dead-reason", idpsession.DeadReason(deadErr)).
		Msg("upstream idp session is no longer valid, deleting session")
	mgr.deleteSession(ctx, sessionID)
}

// deleteSession deletes a session from the databroke, the local data store, and the schedulers
func (mgr *Manager) deleteSession(ctx context.Context, sessionID string) {
	log.Ctx(ctx).Debug().
		Str("session-id", sessionID).
		Msg("deleting session")

	mgr.mu.Lock()
	mgr.dataStore.deleteSession(sessionID)
	if rss, ok := mgr.refreshSessionSchedulers[sessionID]; ok {
		rss.Stop()
		delete(mgr.refreshSessionSchedulers, sessionID)
	}
	mgr.mu.Unlock()

	_, err := storage.DeleteDataBrokerRecord(ctx, mgr.cfg.Load().dataBrokerClient, grpcutil.GetTypeURL(new(session.Session)), sessionID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("session-id", sessionID).
			Msg("failed to delete session")
	}
}

func (mgr *Manager) updateSession(ctx context.Context, s *session.Session) {
	log.Ctx(ctx).Debug().
		Str("user-id", s.GetUserId()).
		Str("session-id", s.GetId()).
		Msg("updating session")

	fm, err := fieldmaskpb.New(s, "oauth_token", "id_token", "claims")
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("failed to create fieldmask for session")
		return
	}

	_, err = session.Patch(ctx, mgr.cfg.Load().dataBrokerClient, s, fm)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("failed to patch updated session record")
		return
	}

	mgr.mu.Lock()
	mgr.dataStore.putSession(s)
	if rss, ok := mgr.refreshSessionSchedulers[s.GetId()]; ok {
		rss.Update(s)
	}
	mgr.mu.Unlock()
}

// updateUser updates the user in the databroker, the local data store, and resets the scheduler.
// (Whenever we refresh a session, we also refresh the user info. By resetting the user info
// scheduler here we can avoid refreshing user info more often than necessary.)
func (mgr *Manager) updateUser(ctx context.Context, u *user.User) {
	log.Ctx(ctx).Debug().
		Str("user-id", u.GetId()).
		Msg("updating user")

	_, err := databroker.Put(ctx, mgr.cfg.Load().dataBrokerClient, u)
	if err != nil {
		log.Ctx(ctx).Error().
			Str("user-id", u.GetId()).
			Err(err).
			Msg("failed to store updated user record")
		return
	}

	mgr.mu.Lock()
	mgr.dataStore.putUser(u)
	if uuis, ok := mgr.updateUserInfoSchedulers[u.GetId()]; ok {
		uuis.Reset()
	}
	mgr.mu.Unlock()
}

func (mgr *Manager) recordLastError(id string, err error) {
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
