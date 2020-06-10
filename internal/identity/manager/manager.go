// Package manager contains an identity manager responsible for refreshing sessions and creating users.
package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"golang.org/x/oauth2"
	"gopkg.in/tomb.v2"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/grpc/user"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/scheduler"
)

// Authenticator is an identity.Provider with only the methods needed by the manager.
type Authenticator interface {
	Refresh(context.Context, *oauth2.Token, interface{}) (*oauth2.Token, error)
	Revoke(context.Context, *oauth2.Token) error
	UpdateUserInfo(ctx context.Context, t *oauth2.Token, v interface{}) error
}

// A Manager refreshes identity information using session and user data.
type Manager struct {
	cfg              *config
	authenticator    Authenticator
	sessionClient    session.SessionServiceClient
	userClient       user.UserServiceClient
	dataBrokerClient databroker.DataBrokerServiceClient

	sessions         sessionCollection
	sessionScheduler *scheduler.Scheduler
	users            userCollection
	userScheduler    *scheduler.Scheduler
}

// New creates a new identity manager.
func New(
	authenticator Authenticator,
	sessionClient session.SessionServiceClient,
	userClient user.UserServiceClient,
	dataBrokerClient databroker.DataBrokerServiceClient,
	options ...Option,
) *Manager {
	mgr := &Manager{
		cfg:              newConfig(options...),
		authenticator:    authenticator,
		sessionClient:    sessionClient,
		userClient:       userClient,
		dataBrokerClient: dataBrokerClient,

		sessions: sessionCollection{
			BTree: btree.New(8),
		},
		sessionScheduler: scheduler.New(),
		users: userCollection{
			BTree: btree.New(8),
		},
		userScheduler: scheduler.New(),
	}
	return mgr
}

// Run runs the manager. This method blocks until an error occurs or the given context is canceled.
func (mgr *Manager) Run(ctx context.Context) error {
	t, ctx := tomb.WithContext(ctx)

	updatedSession := make(chan *session.Session, 1)
	t.Go(func() error {
		return mgr.syncSessions(ctx, updatedSession)
	})

	updatedUser := make(chan *user.User, 1)
	t.Go(func() error {
		return mgr.syncUsers(ctx, updatedUser)
	})

	t.Go(func() error {
		return mgr.refreshLoop(ctx, updatedSession, updatedUser)
	})

	return t.Wait()
}

func (mgr *Manager) refreshLoop(
	ctx context.Context,
	updatedSession <-chan *session.Session,
	updatedUser <-chan *user.User,
) error {
	maxWait := time.Minute * 10

	timer := time.NewTimer(maxWait)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case s := <-updatedSession:
			mgr.onUpdateSession(ctx, s)
		case u := <-updatedUser:
			mgr.onUpdateUser(ctx, u)
		case <-timer.C:
		}

		now := time.Now()
		nextTime := now.Add(maxWait)

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

		// refresh groups
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

		timer.Reset(time.Until(nextTime))
	}
}

func (mgr *Manager) refreshSession(ctx context.Context, userID, sessionID string) {
	log.Info().
		Str("user_id", userID).
		Str("session_id", sessionID).
		Msg("refreshing session")

	s, ok := mgr.sessions.Get(userID, sessionID)
	if !ok {
		log.Warn().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session found for refresh")
		return
	}

	expiry, err := ptypes.Timestamp(s.GetExpiresAt())
	if err == nil && !expiry.After(time.Now()) {
		log.Info().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("deleting expired session")
		s.DeletedAt, _ = ptypes.TimestampProto(time.Now())
		_, err = mgr.sessionClient.Add(ctx, &session.AddRequest{Session: s.Session})
		if err != nil {
			log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to delete session")
			return
		}
		return
	}

	if s.Session == nil || s.Session.OauthToken == nil {
		log.Warn().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session oauth2 token found for refresh")
		return
	}

	newToken, err := mgr.authenticator.Refresh(ctx, fromOAuthToken(s.OauthToken), &s)
	if err != nil {
		log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token")
		return
	}
	s.OauthToken = toOAuthToken(newToken)

	_, err = mgr.sessionClient.Add(ctx, &session.AddRequest{Session: s.Session})
	if err != nil {
		log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update session")
		return
	}

	mgr.onUpdateSession(ctx, s.Session)
}

func (mgr *Manager) refreshUser(ctx context.Context, userID string) {
	log.Info().
		Str("user_id", userID).
		Msg("refreshing user")

	u, ok := mgr.users.Get(userID)
	if !ok {
		log.Warn().
			Str("user_id", userID).
			Msg("no user found for refresh")
		return
	}
	u.lastRefresh = time.Now()
	mgr.userScheduler.Add(u.NextRefresh(), u.GetId())

	for _, s := range mgr.sessions.GetSessionsForUser(userID) {
		if s.Session == nil || s.Session.OauthToken == nil {
			log.Warn().
				Str("user_id", userID).
				Msg("no session oauth2 token found for refresh")
			continue
		}

		err := mgr.authenticator.UpdateUserInfo(ctx, fromOAuthToken(s.OauthToken), &u)
		if err != nil {
			log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user info")
			continue
		}

		_, err = mgr.userClient.Add(ctx, &user.AddRequest{User: u.User})
		if err != nil {
			log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user")
			continue
		}

		mgr.onUpdateUser(ctx, u.User)
	}
}

func (mgr *Manager) syncSessions(ctx context.Context, ch chan<- *session.Session) error {
	log.Info().Str("service", "manager").Msg("syncing sessions")

	any, err := ptypes.MarshalAny(new(session.Session))
	if err != nil {
		return err
	}

	client, err := mgr.dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
		Type: any.GetTypeUrl(),
	})
	if err != nil {
		return fmt.Errorf("error syncing sessions: %w", err)
	}
	for {
		res, err := client.Recv()
		if err != nil {
			return fmt.Errorf("error receiving sessions: %w", err)
		}

		for _, record := range res.GetRecords() {
			log.Info().Str("service", "manager").Interface("session", record.GetData).Msg("session update")

			var pbSession session.Session
			err := ptypes.UnmarshalAny(record.GetData(), &pbSession)
			if err != nil {
				return fmt.Errorf("error unmarshaling session: %w", err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- &pbSession:
			}
		}
	}
}

func (mgr *Manager) syncUsers(ctx context.Context, ch chan<- *user.User) error {
	log.Info().Str("service", "manager").Msg("syncing users")

	any, err := ptypes.MarshalAny(new(user.User))
	if err != nil {
		return err
	}

	client, err := mgr.dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
		Type: any.GetTypeUrl(),
	})
	if err != nil {
		return fmt.Errorf("error syncing users: %w", err)
	}
	for {
		res, err := client.Recv()
		if err != nil {
			return fmt.Errorf("error receiving users: %w", err)
		}

		for _, record := range res.GetRecords() {
			log.Info().Str("service", "manager").Interface("user", record).Msg("user update")

			var pbUser user.User
			err := ptypes.UnmarshalAny(record.GetData(), &pbUser)
			if err != nil {
				return fmt.Errorf("error unmarshaling user: %w", err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- &pbUser:
			}
		}
	}
}

func (mgr *Manager) onUpdateSession(ctx context.Context, pbSession *session.Session) {
	mgr.sessionScheduler.Remove(toSessionSchedulerKey(pbSession.GetUserId(), pbSession.GetId()))

	if pbSession.GetDeletedAt() != nil {
		mgr.sessions.Delete(pbSession.GetUserId(), pbSession.GetId())
		return
	}

	// update session
	s, _ := mgr.sessions.Get(pbSession.GetUserId(), pbSession.GetId())
	s.lastRefresh = time.Now()
	s.gracePeriod = mgr.cfg.sessionRefreshGracePeriod
	s.coolOffDuration = mgr.cfg.sessionRefreshCoolOffDuration
	s.Session = pbSession
	mgr.sessions.ReplaceOrInsert(s)
	mgr.sessionScheduler.Add(s.NextRefresh(), toSessionSchedulerKey(pbSession.GetUserId(), pbSession.GetId()))

	// create the user if it doesn't exist yet
	if _, ok := mgr.users.Get(pbSession.GetUserId()); !ok {
		mgr.createUser(ctx, pbSession)
	}
}

func (mgr *Manager) onUpdateUser(_ context.Context, pbUser *user.User) {
	if pbUser.DeletedAt != nil {
		mgr.users.Delete(pbUser.GetId())
		mgr.userScheduler.Remove(pbUser.GetId())
		return
	}

	u, ok := mgr.users.Get(pbUser.GetId())
	if ok {
		// only reset the refresh time if this is an existing user
		u.lastRefresh = time.Now()
	}
	u.refreshInterval = mgr.cfg.groupRefreshInterval
	u.User = pbUser
	mgr.users.ReplaceOrInsert(u)
	mgr.userScheduler.Add(u.NextRefresh(), u.GetId())
}

func (mgr *Manager) createUser(ctx context.Context, pbSession *session.Session) {
	u := User{
		User: &user.User{
			Id: pbSession.GetUserId(),
		},
	}

	_, err := mgr.userClient.Add(ctx, &user.AddRequest{User: u.User})
	if err != nil {
		log.Error().Err(err).
			Str("user_id", pbSession.GetUserId()).
			Str("session_id", pbSession.GetId()).
			Msg("failed to create user")
	}
}
