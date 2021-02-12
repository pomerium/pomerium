// Package manager contains an identity manager responsible for refreshing sessions and creating users.
package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/identity/identity"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/scheduler"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

const (
	dataBrokerParallelism = 10
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

	sessionScheduler *scheduler.Scheduler
	userScheduler    *scheduler.Scheduler

	sessions        sessionCollection
	users           userCollection
	directoryUsers  map[string]*directory.User
	directoryGroups map[string]*directory.Group

	directoryNextRefresh time.Time

	dataBrokerSemaphore *semaphore.Weighted
}

// New creates a new identity manager.
func New(
	options ...Option,
) *Manager {
	mgr := &Manager{
		cfg: newAtomicConfig(newConfig()),
		log: log.With().Str("service", "identity_manager").Logger(),

		sessionScheduler: scheduler.New(),
		userScheduler:    scheduler.New(),

		directoryGroups: make(map[string]*directory.Group),
		directoryUsers:  make(map[string]*directory.User),
		sessions:        sessionCollection{BTree: btree.New(8)},
		users:           userCollection{BTree: btree.New(8)},

		dataBrokerSemaphore: semaphore.NewWeighted(dataBrokerParallelism),
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
	updatedDirectoryGroup := make(chan *directory.Group, 1)
	updatedDirectoryUser := make(chan *directory.User, 1)
	updatedSession := make(chan sessionMessage, 1)
	updatedUser := make(chan userMessage, 1)
	clear := make(chan struct{}, 1)

	syncer := newDataBrokerSyncer(
		mgr.cfg,
		mgr.log,
		updatedDirectoryGroup,
		updatedDirectoryUser,
		updatedSession,
		updatedUser,
		clear,
	)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return syncer.Run(ctx)
	})
	eg.Go(func() error {
		return mgr.refreshLoop(ctx, updatedSession, updatedUser, updatedDirectoryUser, updatedDirectoryGroup, clear)
	})

	return eg.Wait()
}

func (mgr *Manager) refreshLoop(
	ctx context.Context,
	updatedSession <-chan sessionMessage,
	updatedUser <-chan userMessage,
	updatedDirectoryUser <-chan *directory.User,
	updatedDirectoryGroup <-chan *directory.Group,
	clear <-chan struct{},
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
		case <-clear:
			mgr.directoryGroups = make(map[string]*directory.Group)
			mgr.directoryUsers = make(map[string]*directory.User)
			mgr.sessions = sessionCollection{BTree: btree.New(8)}
			mgr.users = userCollection{BTree: btree.New(8)}
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
	eg, ctx := errgroup.WithContext(ctx)

	lookup := map[string]*directory.Group{}
	for _, dg := range directoryGroups {
		lookup[dg.GetId()] = dg
	}

	for groupID, newDG := range lookup {
		curDG, ok := mgr.directoryGroups[groupID]
		if !ok || !proto.Equal(newDG, curDG) {
			id := newDG.GetId()
			any, err := ptypes.MarshalAny(newDG)
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to marshal directory group")
				return
			}
			eg.Go(func() error {
				if err := mgr.dataBrokerSemaphore.Acquire(ctx, 1); err != nil {
					return err
				}
				defer mgr.dataBrokerSemaphore.Release(1)

				_, err = mgr.cfg.Load().dataBrokerClient.Put(ctx, &databroker.PutRequest{
					Record: &databroker.Record{
						Type: any.GetTypeUrl(),
						Id:   id,
						Data: any,
					},
				})
				if err != nil {
					return fmt.Errorf("failed to update directory group: %s", id)
				}
				return nil
			})
		}
	}

	for groupID, curDG := range mgr.directoryGroups {
		_, ok := lookup[groupID]
		if !ok {
			id := curDG.GetId()
			any, err := ptypes.MarshalAny(curDG)
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to marshal directory group")
				return
			}
			eg.Go(func() error {
				if err := mgr.dataBrokerSemaphore.Acquire(ctx, 1); err != nil {
					return err
				}
				defer mgr.dataBrokerSemaphore.Release(1)

				_, err = mgr.cfg.Load().dataBrokerClient.Put(ctx, &databroker.PutRequest{
					Record: &databroker.Record{
						Type:      any.GetTypeUrl(),
						Id:        id,
						DeletedAt: timestamppb.Now(),
					},
				})
				if err != nil {
					return fmt.Errorf("failed to delete directory group: %s", id)
				}
				return nil
			})
		}
	}
}

func (mgr *Manager) mergeUsers(ctx context.Context, directoryUsers []*directory.User) {
	eg, ctx := errgroup.WithContext(ctx)

	lookup := map[string]*directory.User{}
	for _, du := range directoryUsers {
		lookup[du.GetId()] = du
	}

	for userID, newDU := range lookup {
		curDU, ok := mgr.directoryUsers[userID]
		if !ok || !proto.Equal(newDU, curDU) {
			id := newDU.GetId()
			any, err := ptypes.MarshalAny(newDU)
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to marshal directory user")
				return
			}
			eg.Go(func() error {
				if err := mgr.dataBrokerSemaphore.Acquire(ctx, 1); err != nil {
					return err
				}
				defer mgr.dataBrokerSemaphore.Release(1)

				client := mgr.cfg.Load().dataBrokerClient
				if _, err := client.Put(ctx, &databroker.PutRequest{
					Record: &databroker.Record{
						Type: any.GetTypeUrl(),
						Id:   id,
						Data: any,
					},
				}); err != nil {
					return fmt.Errorf("failed to update directory user: %s", id)
				}
				return nil
			})
		}
	}

	for userID, curDU := range mgr.directoryUsers {
		_, ok := lookup[userID]
		if !ok {
			id := curDU.GetId()
			any, err := ptypes.MarshalAny(curDU)
			if err != nil {
				mgr.log.Warn().Err(err).Msg("failed to marshal directory user")
				return
			}
			eg.Go(func() error {
				if err := mgr.dataBrokerSemaphore.Acquire(ctx, 1); err != nil {
					return err
				}
				defer mgr.dataBrokerSemaphore.Release(1)

				client := mgr.cfg.Load().dataBrokerClient
				if _, err := client.Put(ctx, &databroker.PutRequest{
					Record: &databroker.Record{
						Type:      any.GetTypeUrl(),
						Id:        id,
						Data:      any,
						DeletedAt: timestamppb.Now(),
					},
				}); err != nil {
					return fmt.Errorf("failed to delete directory user (%s): %w", id, err)
				}
				return nil
			})
		}
	}

	if err := eg.Wait(); err != nil {
		mgr.log.Warn().Err(err).Msg("manager: failed to merge users")
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

	res, err := session.Put(ctx, mgr.cfg.Load().dataBrokerClient, s.Session)
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

		record, err := user.Put(ctx, mgr.cfg.Load().dataBrokerClient, u.User)
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

func (mgr *Manager) onUpdateSession(_ context.Context, msg sessionMessage) {
	mgr.sessionScheduler.Remove(toSessionSchedulerKey(msg.session.GetUserId(), msg.session.GetId()))

	if msg.record.GetDeletedAt() != nil {
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
}

func (mgr *Manager) onUpdateUser(_ context.Context, msg userMessage) {
	mgr.userScheduler.Remove(msg.user.GetId())

	if msg.record.GetDeletedAt() != nil {
		mgr.users.Delete(msg.user.GetId())
		return
	}

	u, _ := mgr.users.Get(msg.user.GetId())
	u.lastRefresh = time.Now()
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
