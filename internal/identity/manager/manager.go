// Package manager contains an identity manager responsible for refreshing sessions and creating users.
package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"gopkg.in/tomb.v2"

	"github.com/pomerium/pomerium/internal/directory"
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
	directory        directory.Provider
	sessionClient    session.SessionServiceClient
	userClient       user.UserServiceClient
	dataBrokerClient databroker.DataBrokerServiceClient
	log              zerolog.Logger

	sessions         sessionCollection
	sessionScheduler *scheduler.Scheduler

	users         userCollection
	userScheduler *scheduler.Scheduler

	directoryUsers              map[string]*directory.User
	directoryUsersServerVersion string
	directoryUsersRecordVersion string
	directoryUsersNextRefresh   time.Time
}

// New creates a new identity manager.
func New(
	authenticator Authenticator,
	directoryProvider directory.Provider,
	sessionClient session.SessionServiceClient,
	userClient user.UserServiceClient,
	dataBrokerClient databroker.DataBrokerServiceClient,
	options ...Option,
) *Manager {
	mgr := &Manager{
		cfg:              newConfig(options...),
		authenticator:    authenticator,
		directory:        directoryProvider,
		sessionClient:    sessionClient,
		userClient:       userClient,
		dataBrokerClient: dataBrokerClient,
		log:              log.With().Str("service", "identity_manager").Logger(),

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
	err := mgr.initDirectoryUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize directory users: %w", err)
	}

	t, ctx := tomb.WithContext(ctx)

	updatedSession := make(chan *session.Session, 1)
	t.Go(func() error {
		return mgr.syncSessions(ctx, updatedSession)
	})

	updatedUser := make(chan *user.User, 1)
	t.Go(func() error {
		return mgr.syncUsers(ctx, updatedUser)
	})

	updatedDirectoryUser := make(chan *directory.User, 1)
	t.Go(func() error {
		return mgr.syncDirectoryUsers(ctx, updatedDirectoryUser)
	})

	t.Go(func() error {
		return mgr.refreshLoop(ctx, updatedSession, updatedUser, updatedDirectoryUser)
	})

	return t.Wait()
}

func (mgr *Manager) refreshLoop(
	ctx context.Context,
	updatedSession <-chan *session.Session,
	updatedUser <-chan *user.User,
	updatedDirectoryUser <-chan *directory.User,
) error {
	maxWait := time.Minute * 10
	nextTime := time.Now().Add(maxWait)
	if mgr.directoryUsersNextRefresh.Before(nextTime) {
		nextTime = mgr.directoryUsersNextRefresh
	}

	timer := time.NewTimer(time.Until(nextTime))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case s := <-updatedSession:
			mgr.onUpdateSession(ctx, s)
		case u := <-updatedUser:
			mgr.onUpdateUser(ctx, u)
		case du := <-updatedDirectoryUser:
			mgr.onUpdateDirectoryUser(ctx, du)
		case <-timer.C:
		}

		now := time.Now()
		nextTime := now.Add(maxWait)

		// refresh groups
		if mgr.directoryUsersNextRefresh.Before(now) {
			mgr.refreshDirectoryUsers(ctx)
			mgr.directoryUsersNextRefresh = now.Add(mgr.cfg.groupRefreshInterval)
			if mgr.directoryUsersNextRefresh.Before(nextTime) {
				nextTime = mgr.directoryUsersNextRefresh
			}
		}

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

		timer.Reset(time.Until(nextTime))
	}
}

func (mgr *Manager) refreshDirectoryUsers(ctx context.Context) {
	mgr.log.Info().Msg("refreshing directory users")

	ctx, clearTimeout := context.WithTimeout(ctx, time.Minute)
	defer clearTimeout()

	directoryUsers, err := mgr.directory.UserGroups(ctx)
	if err != nil {
		mgr.log.Warn().Err(err).Msg("failed to refresh directory users and groups")
		return
	}

	lookup := map[string]*directory.User{}
	for _, du := range directoryUsers {
		lookup[du.GetId()] = du
	}

	for userID, newDU := range lookup {
		curDU, ok := mgr.directoryUsers[userID]
		if !ok || !proto.Equal(newDU, curDU) {
			any, err := ptypes.MarshalAny(newDU)
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to marshal directory user")
				return
			}
			_, err = mgr.dataBrokerClient.Set(ctx, &databroker.SetRequest{
				Type: any.GetTypeUrl(),
				Id:   newDU.GetId(),
				Data: any,
			})
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to update directory user")
				return
			}
		}
	}

	for userID, curDU := range mgr.directoryUsers {
		_, ok := lookup[userID]
		if !ok {
			any, err := ptypes.MarshalAny(curDU)
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to marshal directory user")
				return
			}
			_, err = mgr.dataBrokerClient.Delete(ctx, &databroker.DeleteRequest{
				Type: any.GetTypeUrl(),
				Id:   curDU.GetId(),
			})
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to delete directory user")
				return
			}
		}
	}
}

func (mgr *Manager) refreshSession(ctx context.Context, userID, sessionID string) {
	mgr.log.Info().
		Str("user_id", userID).
		Str("session_id", sessionID).
		Msg("refreshing session")

	s, ok := mgr.sessions.Get(userID, sessionID)
	if !ok {
		mgr.log.Warn().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session found for refresh")
		return
	}

	expiry, err := ptypes.Timestamp(s.GetExpiresAt())
	if err == nil && !expiry.After(time.Now()) {
		mgr.log.Info().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("deleting expired session")
		s.DeletedAt, _ = ptypes.TimestampProto(time.Now())
		_, err = mgr.sessionClient.Add(ctx, &session.AddRequest{Session: s.Session})
		if err != nil {
			mgr.log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to delete session")
			return
		}
		return
	}

	if s.Session == nil || s.Session.OauthToken == nil {
		mgr.log.Warn().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session oauth2 token found for refresh")
		return
	}

	newToken, err := mgr.authenticator.Refresh(ctx, fromOAuthToken(s.OauthToken), &s)
	if err != nil {
		mgr.log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token")
		return
	}
	s.OauthToken = toOAuthToken(newToken)

	_, err = mgr.sessionClient.Add(ctx, &session.AddRequest{Session: s.Session})
	if err != nil {
		mgr.log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update session")
		return
	}

	mgr.onUpdateSession(ctx, s.Session)
}

func (mgr *Manager) refreshUser(ctx context.Context, userID string) {
	mgr.log.Info().
		Str("user_id", userID).
		Msg("refreshing user")

	u, ok := mgr.users.Get(userID)
	if !ok {
		mgr.log.Warn().
			Str("user_id", userID).
			Msg("no user found for refresh")
		return
	}
	u.lastRefresh = time.Now()
	mgr.userScheduler.Add(u.NextRefresh(), u.GetId())

	for _, s := range mgr.sessions.GetSessionsForUser(userID) {
		if s.Session == nil || s.Session.OauthToken == nil {
			mgr.log.Warn().
				Str("user_id", userID).
				Msg("no session oauth2 token found for refresh")
			continue
		}

		err := mgr.authenticator.UpdateUserInfo(ctx, fromOAuthToken(s.OauthToken), &u)
		if err != nil {
			mgr.log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user info")
			continue
		}

		_, err = mgr.userClient.Add(ctx, &user.AddRequest{User: u.User})
		if err != nil {
			mgr.log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user")
			continue
		}

		mgr.onUpdateUser(ctx, u.User)
	}
}

func (mgr *Manager) syncSessions(ctx context.Context, ch chan<- *session.Session) error {
	mgr.log.Info().Msg("syncing sessions")

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
			mgr.log.Info().Interface("session", record.GetData).Msg("session update")

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
	mgr.log.Info().Msg("syncing users")

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
			mgr.log.Info().Interface("user", record).Msg("user update")

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

func (mgr *Manager) initDirectoryUsers(ctx context.Context) error {
	mgr.log.Info().Msg("initializing directory users")

	any, err := ptypes.MarshalAny(new(directory.User))
	if err != nil {
		return err
	}

	res, err := mgr.dataBrokerClient.GetAll(ctx, &databroker.GetAllRequest{
		Type: any.GetTypeUrl(),
	})
	if err != nil {
		return fmt.Errorf("error getting all directory users: %w", err)
	}

	mgr.directoryUsers = map[string]*directory.User{}
	for _, record := range res.GetRecords() {
		var pbDirectoryUser directory.User
		err := ptypes.UnmarshalAny(record.GetData(), &pbDirectoryUser)
		if err != nil {
			return fmt.Errorf("error unmarshaling directory user: %w", err)
		}

		mgr.directoryUsers[pbDirectoryUser.GetId()] = &pbDirectoryUser
	}
	mgr.directoryUsersRecordVersion = res.GetRecordVersion()
	mgr.directoryUsersServerVersion = res.GetServerVersion()

	return nil
}

func (mgr *Manager) syncDirectoryUsers(ctx context.Context, ch chan<- *directory.User) error {
	mgr.log.Info().Msg("syncing directory users")

	any, err := ptypes.MarshalAny(new(directory.User))
	if err != nil {
		return err
	}

	client, err := mgr.dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
		Type:          any.GetTypeUrl(),
		ServerVersion: mgr.directoryUsersServerVersion,
		RecordVersion: mgr.directoryUsersRecordVersion,
	})
	if err != nil {
		return fmt.Errorf("error syncing directory users: %w", err)
	}
	for {
		res, err := client.Recv()
		if err != nil {
			return fmt.Errorf("error receiving directory users: %w", err)
		}

		for _, record := range res.GetRecords() {
			mgr.log.Info().Interface("directory_user", record).Msg("directory user update")

			var pbDirectoryUser directory.User
			err := ptypes.UnmarshalAny(record.GetData(), &pbDirectoryUser)
			if err != nil {
				return fmt.Errorf("error unmarshaling directory user: %w", err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- &pbDirectoryUser:
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

func (mgr *Manager) onUpdateDirectoryUser(_ context.Context, pbDirectoryUser *directory.User) {
	mgr.directoryUsers[pbDirectoryUser.GetId()] = pbDirectoryUser
}

func (mgr *Manager) createUser(ctx context.Context, pbSession *session.Session) {
	u := User{
		User: &user.User{
			Id: pbSession.GetUserId(),
		},
	}

	_, err := mgr.userClient.Add(ctx, &user.AddRequest{User: u.User})
	if err != nil {
		mgr.log.Error().Err(err).
			Str("user_id", pbSession.GetUserId()).
			Str("session_id", pbSession.GetId()).
			Msg("failed to create user")
	}
}
