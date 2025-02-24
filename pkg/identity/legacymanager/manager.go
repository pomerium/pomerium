// Package legacymanager contains an identity manager responsible for refreshing sessions and creating users.
package legacymanager

import (
	"context"
	"errors"
	"time"

	"github.com/google/btree"
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
	"github.com/pomerium/pomerium/internal/scheduler"
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
	UpdateUserInfo(context.Context, *oauth2.Token, interface{}) error
}

type (
	updateRecordsMessage struct {
		records []*databroker.Record
	}
)

// A Manager refreshes identity information using session and user data.
type Manager struct {
	enabler.Enabler
	cfg *atomicutil.Value[*config]

	sessionScheduler *scheduler.Scheduler
	userScheduler    *scheduler.Scheduler

	sessions sessionCollection
	users    userCollection
}

// New creates a new identity manager.
func New(
	options ...Option,
) *Manager {
	mgr := &Manager{
		cfg: atomicutil.NewValue(newConfig()),

		sessionScheduler: scheduler.New(),
		userScheduler:    scheduler.New(),
	}
	mgr.Enabler = enabler.New("identity_manager", mgr, true)
	mgr.reset()
	mgr.UpdateConfig(options...)
	return mgr
}

func withLog(ctx context.Context) context.Context {
	return log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "identity_manager")
	})
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

// RunEnabled runs the manager. This method blocks until an error occurs or the given context is canceled.
func (mgr *Manager) RunEnabled(ctx context.Context) error {
	leaser := databroker.NewLeaser("identity_manager", mgr.cfg.Load().leaseTTL, mgr)
	return leaser.Run(ctx)
}

// RunLeased runs the identity manager when a lease is acquired.
func (mgr *Manager) RunLeased(ctx context.Context) error {
	ctx = withLog(ctx)
	update := make(chan updateRecordsMessage, 1)
	clear := make(chan struct{}, 1)

	syncer := newDataBrokerSyncer(ctx, mgr.cfg, update, clear)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return syncer.Run(ctx)
	})
	eg.Go(func() error {
		return mgr.refreshLoop(ctx, update, clear)
	})

	return eg.Wait()
}

// GetDataBrokerServiceClient gets the databroker client.
func (mgr *Manager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return mgr.cfg.Load().dataBrokerClient
}

func (mgr *Manager) now() time.Time {
	return mgr.cfg.Load().now()
}

func (mgr *Manager) refreshLoop(ctx context.Context, update <-chan updateRecordsMessage, clear <-chan struct{}) error {
	// wait for initial sync
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-clear:
		mgr.reset()
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case msg := <-update:
		mgr.onUpdateRecords(ctx, msg)
	}

	log.Ctx(ctx).Debug().
		Int("sessions", mgr.sessions.Len()).
		Int("users", mgr.users.Len()).
		Msg("initial sync complete")

	// start refreshing
	maxWait := time.Minute * 10
	var nextTime time.Time

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-clear:
			mgr.reset()
		case msg := <-update:
			mgr.onUpdateRecords(ctx, msg)
		case <-timer.C:
		}

		now := mgr.now()
		nextTime = now.Add(maxWait)

		// refresh sessions
		for {
			tm, key := mgr.sessionScheduler.Next()
			if now.Before(tm) {
				if tm.Before(nextTime) {
					nextTime = tm
				}
				break
			}
			mgr.sessionScheduler.Remove(key)

			userID, sessionID := fromSessionSchedulerKey(key)
			mgr.refreshSession(ctx, userID, sessionID)
		}

		// refresh users
		for {
			tm, key := mgr.userScheduler.Next()
			if now.Before(tm) {
				if tm.Before(nextTime) {
					nextTime = tm
				}
				break
			}
			mgr.userScheduler.Remove(key)

			mgr.refreshUser(ctx, key)
		}

		metrics.RecordIdentityManagerLastRefresh(ctx)
		timer.Reset(time.Until(nextTime))
	}
}

// refreshSession handles two distinct session lifecycle events:
//
//  1. If the session itself has expired, delete the session.
//  2. If the session's underlying OAuth2 access token is nearing expiration
//     (but the session itself is still valid), refresh the access token.
//
// After a successful access token refresh, this method will also trigger a
// user info refresh. If an access token refresh or a user info refresh fails
// with a permanent error, the session will be deleted.
func (mgr *Manager) refreshSession(ctx context.Context, userID, sessionID string) {
	log.Ctx(ctx).Info().
		Str("user_id", userID).
		Str("session_id", sessionID).
		Msg("refreshing session")

	s, ok := mgr.sessions.Get(userID, sessionID)
	if !ok {
		log.Ctx(ctx).Info().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session found for refresh")
		return
	}

	s.lastRefresh = mgr.now()

	if mgr.refreshSessionInternal(ctx, userID, sessionID, &s) {
		mgr.sessions.ReplaceOrInsert(s)
		mgr.sessionScheduler.Add(s.NextRefresh(), toSessionSchedulerKey(userID, sessionID))
	}
}

// refreshSessionInternal performs the core refresh logic and returns true if
// the session should be scheduled for refresh again, or false if not.
func (mgr *Manager) refreshSessionInternal(
	ctx context.Context, userID, sessionID string, s *Session,
) bool {
	authenticator := mgr.cfg.Load().authenticator
	if authenticator == nil {
		log.Ctx(ctx).Info().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no authenticator defined, deleting session")
		mgr.deleteSession(ctx, userID, sessionID)
		return false
	}

	expiry := s.GetExpiresAt().AsTime()
	if !expiry.After(mgr.now()) {
		log.Ctx(ctx).Info().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("deleting expired session")
		mgr.deleteSession(ctx, userID, sessionID)
		return false
	}

	if s.GetRefreshDisabled() {
		// refresh was explicitly disabled
		return false
	}

	if s.Session == nil || s.Session.OauthToken == nil {
		log.Ctx(ctx).Info().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session oauth2 token found for refresh")
		return false
	}

	newToken, err := authenticator.Refresh(ctx, FromOAuthToken(s.OauthToken), s)
	metrics.RecordIdentityManagerSessionRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
	if isTemporaryError(err) {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token")
		return true
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token, deleting session")
		mgr.deleteSession(ctx, userID, sessionID)
		return false
	}
	s.OauthToken = ToOAuthToken(newToken)

	err = authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), s)
	metrics.RecordIdentityManagerUserRefresh(ctx, err)
	mgr.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
	if isTemporaryError(err) {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update user info")
		return true
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update user info, deleting session")
		mgr.deleteSession(ctx, userID, sessionID)
		return false
	}

	fm, err := fieldmaskpb.New(s.Session, "oauth_token", "id_token", "claims")
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("internal error")
		return false
	}

	if _, err := session.Patch(ctx, mgr.cfg.Load().dataBrokerClient, s.Session, fm); err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update session")
	}
	return true
}

func (mgr *Manager) refreshUser(ctx context.Context, userID string) {
	log.Ctx(ctx).Info().
		Str("user_id", userID).
		Msg("refreshing user")

	authenticator := mgr.cfg.Load().authenticator
	if authenticator == nil {
		return
	}

	u, ok := mgr.users.Get(userID)
	if !ok {
		log.Ctx(ctx).Info().
			Str("user_id", userID).
			Msg("no user found for refresh")
		return
	}
	u.lastRefresh = mgr.now()
	mgr.userScheduler.Add(u.NextRefresh(), u.GetId())

	for _, s := range mgr.sessions.GetSessionsForUser(userID) {
		if s.Session == nil || s.Session.OauthToken == nil {
			log.Ctx(ctx).Info().
				Str("user_id", userID).
				Msg("no session oauth2 token found for refresh")
			continue
		}

		err := authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), &u)
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
			mgr.deleteSession(ctx, userID, s.GetId())
			continue
		}

		res, err := databroker.Put(ctx, mgr.cfg.Load().dataBrokerClient, u.User)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user")
			continue
		}

		mgr.onUpdateUser(ctx, res.GetRecords()[0], u.User)
	}
}

func (mgr *Manager) onUpdateRecords(ctx context.Context, msg updateRecordsMessage) {
	for _, record := range msg.records {
		switch record.GetType() {
		case grpcutil.GetTypeURL(new(session.Session)):
			var pbSession session.Session
			err := record.GetData().UnmarshalTo(&pbSession)
			if err != nil {
				log.Ctx(ctx).Error().Msgf("error unmarshaling session: %s", err)
				continue
			}
			mgr.onUpdateSession(record, &pbSession)
		case grpcutil.GetTypeURL(new(user.User)):
			var pbUser user.User
			err := record.GetData().UnmarshalTo(&pbUser)
			if err != nil {
				log.Ctx(ctx).Error().Msgf("error unmarshaling user: %s", err)
				continue
			}
			mgr.onUpdateUser(ctx, record, &pbUser)
		}
	}
}

func (mgr *Manager) onUpdateSession(record *databroker.Record, session *session.Session) {
	mgr.sessionScheduler.Remove(toSessionSchedulerKey(session.GetUserId(), session.GetId()))

	if record.GetDeletedAt() != nil {
		mgr.sessions.Delete(session.GetUserId(), session.GetId())
		return
	}

	// update session
	s, _ := mgr.sessions.Get(session.GetUserId(), session.GetId())
	if s.lastRefresh.IsZero() {
		s.lastRefresh = mgr.now()
	}
	s.gracePeriod = mgr.cfg.Load().sessionRefreshGracePeriod
	s.coolOffDuration = mgr.cfg.Load().sessionRefreshCoolOffDuration
	s.Session = session
	mgr.sessions.ReplaceOrInsert(s)
	mgr.sessionScheduler.Add(s.NextRefresh(), toSessionSchedulerKey(session.GetUserId(), session.GetId()))
}

func (mgr *Manager) onUpdateUser(_ context.Context, record *databroker.Record, user *user.User) {
	mgr.userScheduler.Remove(user.GetId())

	if record.GetDeletedAt() != nil {
		mgr.users.Delete(user.GetId())
		return
	}

	u, _ := mgr.users.Get(user.GetId())
	u.lastRefresh = mgr.cfg.Load().now()
	u.User = user
	mgr.users.ReplaceOrInsert(u)
	mgr.userScheduler.Add(u.NextRefresh(), u.GetId())
}

func (mgr *Manager) deleteSession(ctx context.Context, userID, sessionID string) {
	mgr.sessionScheduler.Remove(toSessionSchedulerKey(userID, sessionID))
	mgr.sessions.Delete(userID, sessionID)

	client := mgr.cfg.Load().dataBrokerClient
	res, err := client.Get(ctx, &databroker.GetRequest{
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

	_, err = client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{record},
	})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("session_id", sessionID).
			Msg("failed to delete session")
		return
	}
}

// reset resets all the manager datastructures to their initial state
func (mgr *Manager) reset() {
	mgr.sessions = sessionCollection{BTree: btree.New(8)}
	mgr.users = userCollection{BTree: btree.New(8)}
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

func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var hasTemporary interface{ Temporary() bool }
	if errors.As(err, &hasTemporary) && hasTemporary.Temporary() {
		return true
	}
	return false
}
