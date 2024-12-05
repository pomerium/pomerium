// Package manager contains an identity manager responsible for refreshing sessions and creating users.
package manager

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/enabler"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/identity/identity"
	metrics_ids "github.com/pomerium/pomerium/pkg/metrics"
)

// Authenticator is an identity.Provider with only the methods needed by the manager.
type Authenticator interface {
	Refresh(context.Context, *oauth2.Token, identity.State) (*oauth2.Token, error)
	Revoke(context.Context, *oauth2.Token) error
	UpdateUserInfo(context.Context, *oauth2.Token, any) error
}

// A Manager refreshes identity information using session and user data.
type Manager struct {
	enabler.Enabler
	cfg *atomicutil.Value[*config]

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
		cfg: atomicutil.NewValue(newConfig()),

		dataStore:                newDataStore(),
		refreshSessionSchedulers: make(map[string]*refreshSessionScheduler),
		updateUserInfoSchedulers: make(map[string]*updateUserInfoScheduler),
	}
	mgr.Enabler = enabler.New("identity_manager", mgr, true)
	mgr.UpdateConfig(options...)
	return mgr
}

// UpdateConfig updates the manager with the new options.
func (mgr *Manager) UpdateConfig(options ...Option) {
	mgr.cfg.Store(newConfig(options...))
	if mgr.cfg.Load().enabled {
		mgr.Enable()
	} else {
		mgr.Disable()
	}
}

// GetDataBrokerServiceClient gets the databroker client.
func (mgr *Manager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.cfg.Load().dataBrokerClient
}

// RunEnabled runs the manager. This method blocks until an error occurs or the given context is canceled.
func (mgr *Manager) RunEnabled(ctx context.Context) error {
	leaser := databroker.NewLeaser("identity_manager", mgr.cfg.Load().leaseTTL, mgr)
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
	log.Ctx(ctx).Debug().Msg("all session deleted")

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
	log.Ctx(ctx).Debug().Str("session_id", sessionID).Msg("session deleted")

	mgr.mu.Lock()
	mgr.dataStore.deleteSession(sessionID)
	if rss, ok := mgr.refreshSessionSchedulers[sessionID]; ok {
		rss.Stop()
		delete(mgr.refreshSessionSchedulers, sessionID)
	}
	mgr.mu.Unlock()
}

func (mgr *Manager) onDeleteUser(ctx context.Context, userID string) {
	log.Ctx(ctx).Debug().Str("user_id", userID).Msg("user deleted")

	mgr.mu.Lock()
	mgr.dataStore.deleteUser(userID)
	if uuis, ok := mgr.updateUserInfoSchedulers[userID]; ok {
		uuis.Stop()
		delete(mgr.updateUserInfoSchedulers, userID)
	}
	mgr.mu.Unlock()
}

func (mgr *Manager) onUpdateSession(ctx context.Context, s *session.Session) {
	log.Ctx(ctx).Debug().Str("session_id", s.GetId()).Msg("session updated")

	mgr.mu.Lock()
	mgr.dataStore.putSession(s)
	rss, ok := mgr.refreshSessionSchedulers[s.GetId()]
	if !ok {
		rss = newRefreshSessionScheduler(
			ctx,
			mgr.cfg.Load().now,
			mgr.cfg.Load().sessionRefreshGracePeriod,
			mgr.cfg.Load().sessionRefreshCoolOffDuration,
			mgr.refreshSession,
			s.GetId(),
		)
		mgr.refreshSessionSchedulers[s.GetId()] = rss
	}
	rss.Update(s)
	mgr.mu.Unlock()
}

func (mgr *Manager) onUpdateUser(ctx context.Context, u *user.User) {
	log.Ctx(ctx).Debug().Str("user_id", u.GetId()).Msg("user updated")

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
		Str("session_id", sessionID).
		Msg("refreshing session")

	mgr.mu.Lock()
	s, u := mgr.dataStore.getSessionAndUser(sessionID)
	mgr.mu.Unlock()

	if s == nil {
		log.Ctx(ctx).Info().
			Str("user_id", u.GetId()).
			Str("session_id", sessionID).
			Msg("no session found for refresh")
		return
	}

	authenticator := mgr.cfg.Load().authenticator
	if authenticator == nil {
		log.Ctx(ctx).Info().
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("no authenticator defined, deleting session")
		mgr.deleteSession(ctx, sessionID)
		return
	}

	expiry := s.GetExpiresAt().AsTime()
	if !expiry.After(mgr.cfg.Load().now()) {
		log.Ctx(ctx).Info().
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("deleting expired session")
		mgr.deleteSession(ctx, sessionID)
		return
	}

	if s.GetOauthToken() == nil {
		log.Ctx(ctx).Info().
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("no session oauth2 token found for refresh")
		return
	}

	newToken, err := authenticator.Refresh(ctx, FromOAuthToken(s.OauthToken), newSessionUnmarshaler(s))
	metrics.RecordIdentityManagerSessionRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
	if isTemporaryError(err) {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token")
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token, deleting session")
		mgr.deleteSession(ctx, sessionID)
		return
	}
	s.OauthToken = ToOAuthToken(newToken)

	err = authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), newMultiUnmarshaler(newUserUnmarshaler(u), newSessionUnmarshaler(s)))
	metrics.RecordIdentityManagerUserRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
	if isTemporaryError(err) {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update user info")
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update user info, deleting session")
		mgr.deleteSession(ctx, sessionID)
		return
	}

	mgr.updateSession(ctx, s)
	if u != nil {
		mgr.updateUser(ctx, u)
	}
}

func (mgr *Manager) updateUserInfo(ctx context.Context, userID string) {
	log.Ctx(ctx).Info().Str("user_id", userID).Msg("updating user info")

	authenticator := mgr.cfg.Load().authenticator
	if authenticator == nil {
		return
	}

	mgr.mu.Lock()
	u, ss := mgr.dataStore.getUserAndSessions(userID)
	mgr.mu.Unlock()

	if u == nil {
		log.Ctx(ctx).Error().
			Str("user_id", userID).
			Msg("no user found for update")
		return
	}

	for _, s := range ss {
		if s.GetOauthToken() == nil {
			log.Ctx(ctx).Error().
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("no session oauth2 token found for updating user info")
			continue
		}

		err := authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.GetOauthToken()), newUserUnmarshaler(u))
		metrics.RecordIdentityManagerUserRefresh(ctx, err)
		mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
		if isTemporaryError(err) {
			log.Ctx(ctx).Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user info")
			continue
		} else if err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user info, deleting session")
			mgr.deleteSession(ctx, s.GetId())
			continue
		}

		mgr.updateUser(ctx, u)
	}
}

// deleteSession deletes a session from the databroke, the local data store, and the schedulers
func (mgr *Manager) deleteSession(ctx context.Context, sessionID string) {
	log.Ctx(ctx).Debug().
		Str("session_id", sessionID).
		Msg("deleting session")

	mgr.mu.Lock()
	mgr.dataStore.deleteSession(sessionID)
	if rss, ok := mgr.refreshSessionSchedulers[sessionID]; ok {
		rss.Stop()
		delete(mgr.refreshSessionSchedulers, sessionID)
	}
	mgr.mu.Unlock()

	res, err := mgr.cfg.Load().dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(session.Session)),
		Id:   sessionID,
	})
	if status.Code(err) == codes.NotFound {
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("session_id", sessionID).
			Msg("failed to delete session")
		return
	}

	record := res.GetRecord()
	record.DeletedAt = timestamppb.Now()

	_, err = mgr.cfg.Load().dataBrokerClient.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{record},
	})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("session_id", sessionID).
			Msg("failed to delete session")
		return
	}
}

func (mgr *Manager) updateSession(ctx context.Context, s *session.Session) {
	log.Ctx(ctx).Debug().
		Str("user_id", s.GetUserId()).
		Str("session_id", s.GetId()).
		Msg("updating session")

	fm, err := fieldmaskpb.New(s, "oauth_token", "id_token", "claims")
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to create fieldmask for session")
		return
	}

	_, err = session.Patch(ctx, mgr.cfg.Load().dataBrokerClient, s, fm)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
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
		Str("user_id", u.GetId()).
		Msg("updating user")

	_, err := databroker.Put(ctx, mgr.cfg.Load().dataBrokerClient, u)
	if err != nil {
		log.Ctx(ctx).Error().
			Str("user_id", u.GetId()).
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
