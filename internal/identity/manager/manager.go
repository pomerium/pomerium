// Package manager contains an identity manager responsible for refreshing sessions and creating users.
package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"gopkg.in/tomb.v2"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/identity/identity"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/scheduler"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

// Authenticator is an identity.Provider with only the methods needed by the manager.
type Authenticator interface {
	Refresh(context.Context, *oauth2.Token, identity.State) (*oauth2.Token, error)
	Revoke(context.Context, *oauth2.Token) error
	UpdateUserInfo(context.Context, *oauth2.Token, interface{}) error
}

type (
	sessionMessage struct {
		record  *databroker.Record
		session *session.Session
	}
	userMessage struct {
		record *databroker.Record
		user   *user.User
	}
)

// A Manager refreshes identity information using session and user data.
type Manager struct {
	cfg *atomicConfig
	log zerolog.Logger

	sessions         sessionCollection
	sessionScheduler *scheduler.Scheduler

	users         userCollection
	userScheduler *scheduler.Scheduler

	directoryUsers              map[string]*directory.User
	directoryUsersServerVersion string
	directoryUsersRecordVersion string

	directoryGroups              map[string]*directory.Group
	directoryGroupsServerVersion string
	directoryGroupsRecordVersion string

	directoryNextRefresh time.Time
}

// New creates a new identity manager.
func New(
	options ...Option,
) *Manager {
	mgr := &Manager{
		cfg: newAtomicConfig(newConfig()),
		log: log.With().Str("service", "identity_manager").Logger(),

		sessions: sessionCollection{
			BTree: btree.New(8),
		},
		sessionScheduler: scheduler.New(),
		users: userCollection{
			BTree: btree.New(8),
		},
		userScheduler: scheduler.New(),
	}
	mgr.UpdateConfig(options...)
	return mgr
}

// UpdateConfig updates the manager with the new options.
func (mgr *Manager) UpdateConfig(options ...Option) {
	mgr.cfg.Store(newConfig(options...))
}

// Run runs the manager. This method blocks until an error occurs or the given context is canceled.
func (mgr *Manager) Run(ctx context.Context) error {
	err := mgr.initDirectoryGroups(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize directory groups: %w", err)
	}

	err = mgr.initDirectoryUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize directory users: %w", err)
	}

	t, ctx := tomb.WithContext(ctx)

	updatedSession := make(chan sessionMessage, 1)
	t.Go(func() error {
		return mgr.syncSessions(ctx, updatedSession)
	})

	updatedUser := make(chan userMessage, 1)
	t.Go(func() error {
		return mgr.syncUsers(ctx, updatedUser)
	})

	updatedDirectoryGroup := make(chan *directory.Group, 1)
	t.Go(func() error {
		return mgr.syncDirectoryGroups(ctx, updatedDirectoryGroup)
	})

	updatedDirectoryUser := make(chan *directory.User, 1)
	t.Go(func() error {
		return mgr.syncDirectoryUsers(ctx, updatedDirectoryUser)
	})

	t.Go(func() error {
		return mgr.refreshLoop(ctx, updatedSession, updatedUser, updatedDirectoryUser, updatedDirectoryGroup)
	})

	return t.Wait()
}

func (mgr *Manager) refreshLoop(
	ctx context.Context,
	updatedSession <-chan sessionMessage,
	updatedUser <-chan userMessage,
	updatedDirectoryUser <-chan *directory.User,
	updatedDirectoryGroup <-chan *directory.Group,
) error {
	maxWait := time.Minute * 10
	nextTime := time.Now().Add(maxWait)
	if mgr.directoryNextRefresh.Before(nextTime) {
		nextTime = mgr.directoryNextRefresh
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
		case dg := <-updatedDirectoryGroup:
			mgr.onUpdateDirectoryGroup(ctx, dg)
		case <-timer.C:
		}

		now := time.Now()
		nextTime = now.Add(maxWait)

		// refresh groups
		if mgr.directoryNextRefresh.Before(now) {
			mgr.refreshDirectoryUserGroups(ctx)
			mgr.directoryNextRefresh = now.Add(mgr.cfg.Load().groupRefreshInterval)
		}
		if mgr.directoryNextRefresh.Before(nextTime) {
			nextTime = mgr.directoryNextRefresh
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

func (mgr *Manager) refreshDirectoryUserGroups(ctx context.Context) {
	mgr.log.Info().Msg("refreshing directory users")

	ctx, clearTimeout := context.WithTimeout(ctx, mgr.cfg.Load().groupRefreshTimeout)
	defer clearTimeout()

	directoryGroups, directoryUsers, err := mgr.cfg.Load().directory.UserGroups(ctx)
	if err != nil {
		msg := "failed to refresh directory users and groups"
		if ctx.Err() != nil {
			msg += ". You may need to increase the identity provider directory timeout setting"
			msg += "(https://www.pomerium.io/reference/#identity-provider-refresh-directory-settings)"
		}
		mgr.log.Warn().Err(err).Msg(msg)
		return
	}

	mgr.mergeGroups(ctx, directoryGroups)
	mgr.mergeUsers(ctx, directoryUsers)
}

func (mgr *Manager) mergeGroups(ctx context.Context, directoryGroups []*directory.Group) {
	lookup := map[string]*directory.Group{}
	for _, dg := range directoryGroups {
		lookup[dg.GetId()] = dg
	}

	for groupID, newDG := range lookup {
		curDG, ok := mgr.directoryGroups[groupID]
		if !ok || !proto.Equal(newDG, curDG) {
			any, err := ptypes.MarshalAny(newDG)
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to marshal directory group")
				return
			}
			_, err = mgr.cfg.Load().dataBrokerClient.Set(ctx, &databroker.SetRequest{
				Type: any.GetTypeUrl(),
				Id:   newDG.GetId(),
				Data: any,
			})
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to update directory group")
				return
			}
		}
	}

	for groupID, curDG := range mgr.directoryGroups {
		_, ok := lookup[groupID]
		if !ok {
			any, err := ptypes.MarshalAny(curDG)
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to marshal directory group")
				return
			}
			_, err = mgr.cfg.Load().dataBrokerClient.Delete(ctx, &databroker.DeleteRequest{
				Type: any.GetTypeUrl(),
				Id:   curDG.GetId(),
			})
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to delete directory group")
				return
			}
		}
	}
}

func (mgr *Manager) mergeUsers(ctx context.Context, directoryUsers []*directory.User) {
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
			_, err = mgr.cfg.Load().dataBrokerClient.Set(ctx, &databroker.SetRequest{
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
			_, err = mgr.cfg.Load().dataBrokerClient.Delete(ctx, &databroker.DeleteRequest{
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
		mgr.deleteSession(ctx, s.Session)
		return
	}

	if s.Session == nil || s.Session.OauthToken == nil {
		mgr.log.Warn().
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session oauth2 token found for refresh")
		return
	}

	newToken, err := mgr.cfg.Load().authenticator.Refresh(ctx, FromOAuthToken(s.OauthToken), &s)
	if isTemporaryError(err) {
		mgr.log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token")
		return
	} else if err != nil {
		mgr.log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token, deleting session")
		mgr.deleteSession(ctx, s.Session)
		return
	}
	s.OauthToken = ToOAuthToken(newToken)

	err = mgr.cfg.Load().authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), &s)
	if isTemporaryError(err) {
		mgr.log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update user info")
		return
	} else if err != nil {
		mgr.log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update user info, deleting session")
		mgr.deleteSession(ctx, s.Session)
		return
	}

	res, err := session.Set(ctx, mgr.cfg.Load().dataBrokerClient, s.Session)
	if err != nil {
		mgr.log.Error().Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update session")
		return
	}

	mgr.onUpdateSession(ctx, sessionMessage{record: res.GetRecord(), session: s.Session})
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

		err := mgr.cfg.Load().authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), &u)
		if isTemporaryError(err) {
			mgr.log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user info")
			return
		} else if err != nil {
			mgr.log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user info, deleting session")
			mgr.deleteSession(ctx, s.Session)
			continue
		}

		record, err := user.Set(ctx, mgr.cfg.Load().dataBrokerClient, u.User)
		if err != nil {
			mgr.log.Error().Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user")
			continue
		}

		mgr.onUpdateUser(ctx, userMessage{record: record, user: u.User})
	}
}

func (mgr *Manager) syncSessions(ctx context.Context, ch chan<- sessionMessage) error {
	mgr.log.Info().Msg("syncing sessions")

	any, err := ptypes.MarshalAny(new(session.Session))
	if err != nil {
		return err
	}

	client, err := mgr.cfg.Load().dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
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
			var pbSession session.Session
			err := ptypes.UnmarshalAny(record.GetData(), &pbSession)
			if err != nil {
				return fmt.Errorf("error unmarshaling session: %w", err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- sessionMessage{record: record, session: &pbSession}:
			}
		}
	}
}

func (mgr *Manager) syncUsers(ctx context.Context, ch chan<- userMessage) error {
	mgr.log.Info().Msg("syncing users")

	any, err := ptypes.MarshalAny(new(user.User))
	if err != nil {
		return err
	}

	client, err := mgr.cfg.Load().dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
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
			var pbUser user.User
			err := ptypes.UnmarshalAny(record.GetData(), &pbUser)
			if err != nil {
				return fmt.Errorf("error unmarshaling user: %w", err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- userMessage{record: record, user: &pbUser}:
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

	res, err := mgr.cfg.Load().dataBrokerClient.GetAll(ctx, &databroker.GetAllRequest{
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

	client, err := mgr.cfg.Load().dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
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

func (mgr *Manager) initDirectoryGroups(ctx context.Context) error {
	mgr.log.Info().Msg("initializing directory groups")

	any, err := ptypes.MarshalAny(new(directory.Group))
	if err != nil {
		return err
	}

	res, err := mgr.cfg.Load().dataBrokerClient.GetAll(ctx, &databroker.GetAllRequest{
		Type: any.GetTypeUrl(),
	})
	if err != nil {
		return fmt.Errorf("error getting all directory groups: %w", err)
	}

	mgr.directoryGroups = map[string]*directory.Group{}
	for _, record := range res.GetRecords() {
		var pbDirectoryGroup directory.Group
		err := ptypes.UnmarshalAny(record.GetData(), &pbDirectoryGroup)
		if err != nil {
			return fmt.Errorf("error unmarshaling directory group: %w", err)
		}

		mgr.directoryGroups[pbDirectoryGroup.GetId()] = &pbDirectoryGroup
	}
	mgr.directoryGroupsRecordVersion = res.GetRecordVersion()
	mgr.directoryGroupsServerVersion = res.GetServerVersion()

	return nil
}

func (mgr *Manager) syncDirectoryGroups(ctx context.Context, ch chan<- *directory.Group) error {
	mgr.log.Info().Msg("syncing directory groups")

	any, err := ptypes.MarshalAny(new(directory.Group))
	if err != nil {
		return err
	}

	client, err := mgr.cfg.Load().dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
		Type:          any.GetTypeUrl(),
		ServerVersion: mgr.directoryGroupsServerVersion,
		RecordVersion: mgr.directoryGroupsRecordVersion,
	})
	if err != nil {
		return fmt.Errorf("error syncing directory groups: %w", err)
	}
	for {
		res, err := client.Recv()
		if err != nil {
			return fmt.Errorf("error receiving directory groups: %w", err)
		}

		for _, record := range res.GetRecords() {
			var pbDirectoryGroup directory.Group
			err := ptypes.UnmarshalAny(record.GetData(), &pbDirectoryGroup)
			if err != nil {
				return fmt.Errorf("error unmarshaling directory group: %w", err)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- &pbDirectoryGroup:
			}
		}
	}
}

func (mgr *Manager) onUpdateSession(ctx context.Context, msg sessionMessage) {
	mgr.sessionScheduler.Remove(toSessionSchedulerKey(msg.session.GetUserId(), msg.session.GetId()))

	if msg.record.GetDeletedAt() != nil {
		// remove from local store
		mgr.sessions.Delete(msg.session.GetUserId(), msg.session.GetId())
		return
	}

	// update session
	s, _ := mgr.sessions.Get(msg.session.GetUserId(), msg.session.GetId())
	s.lastRefresh = time.Now()
	s.gracePeriod = mgr.cfg.Load().sessionRefreshGracePeriod
	s.coolOffDuration = mgr.cfg.Load().sessionRefreshCoolOffDuration
	s.Session = msg.session
	mgr.sessions.ReplaceOrInsert(s)
	mgr.sessionScheduler.Add(s.NextRefresh(), toSessionSchedulerKey(msg.session.GetUserId(), msg.session.GetId()))

	// create the user if it doesn't exist yet
	if _, ok := mgr.users.Get(msg.session.GetUserId()); !ok {
		mgr.createUser(ctx, msg.session)
	}
}

func (mgr *Manager) onUpdateUser(_ context.Context, msg userMessage) {
	if msg.record.DeletedAt != nil {
		mgr.users.Delete(msg.user.GetId())
		mgr.userScheduler.Remove(msg.user.GetId())
		return
	}

	u, ok := mgr.users.Get(msg.user.GetId())
	if ok {
		// only reset the refresh time if this is an existing user
		u.lastRefresh = time.Now()
	}
	u.refreshInterval = mgr.cfg.Load().groupRefreshInterval
	u.User = msg.user
	mgr.users.ReplaceOrInsert(u)
	mgr.userScheduler.Add(u.NextRefresh(), u.GetId())
}

func (mgr *Manager) onUpdateDirectoryUser(_ context.Context, pbDirectoryUser *directory.User) {
	mgr.directoryUsers[pbDirectoryUser.GetId()] = pbDirectoryUser
}

func (mgr *Manager) onUpdateDirectoryGroup(_ context.Context, pbDirectoryGroup *directory.Group) {
	mgr.directoryGroups[pbDirectoryGroup.GetId()] = pbDirectoryGroup
}

func (mgr *Manager) createUser(ctx context.Context, pbSession *session.Session) {
	u := User{
		User: &user.User{
			Id: pbSession.GetUserId(),
		},
	}

	_, err := user.Set(ctx, mgr.cfg.Load().dataBrokerClient, u.User)
	if err != nil {
		mgr.log.Error().Err(err).
			Str("user_id", pbSession.GetUserId()).
			Str("session_id", pbSession.GetId()).
			Msg("failed to create user")
	}
}

func (mgr *Manager) deleteSession(ctx context.Context, pbSession *session.Session) {
	err := session.Delete(ctx, mgr.cfg.Load().dataBrokerClient, pbSession.GetId())
	if err != nil {
		mgr.log.Error().Err(err).
			Str("session_id", pbSession.GetId()).
			Msg("failed to delete session")
	}
}

func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if e, ok := err.(interface{ Temporary() bool }); ok && e.Temporary() {
		return true
	}
	return false
}
