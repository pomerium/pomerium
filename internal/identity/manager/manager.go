// Package manager contains an identity manager responsible for refreshing sessions and creating users.
package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/btree"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/identity/identity"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/scheduler"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
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
	updateRecordsMessage struct {
		records []*databroker.Record
	}
)

// A Manager refreshes identity information using session and user data.
type Manager struct {
	cfg *atomicConfig

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

		sessionScheduler: scheduler.New(),
		userScheduler:    scheduler.New(),

		dataBrokerSemaphore: semaphore.NewWeighted(dataBrokerParallelism),
	}
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
}

// Run runs the manager. This method blocks until an error occurs or the given context is canceled.
func (mgr *Manager) Run(ctx context.Context) error {
	locker := databroker.NewLocker("identity_manager", time.Second*30, mgr)
	return locker.Run(ctx)
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

func (mgr *Manager) refreshLoop(ctx context.Context, update <-chan updateRecordsMessage, clear <-chan struct{}) error {
	// wait for initial sync
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-clear:
		mgr.directoryGroups = make(map[string]*directory.Group)
		mgr.directoryUsers = make(map[string]*directory.User)
		mgr.sessions = sessionCollection{BTree: btree.New(8)}
		mgr.users = userCollection{BTree: btree.New(8)}
	}
	select {
	case <-ctx.Done():
	case msg := <-update:
		mgr.onUpdateRecords(ctx, msg)
	}

	log.Info(ctx).
		Int("directory_groups", len(mgr.directoryGroups)).
		Int("directory_users", len(mgr.directoryUsers)).
		Int("sessions", mgr.sessions.Len()).
		Int("users", mgr.users.Len()).
		Msg("initial sync complete")

	// start refreshing
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
		case <-clear:
			mgr.directoryGroups = make(map[string]*directory.Group)
			mgr.directoryUsers = make(map[string]*directory.User)
			mgr.sessions = sessionCollection{BTree: btree.New(8)}
			mgr.users = userCollection{BTree: btree.New(8)}
		case msg := <-update:
			mgr.onUpdateRecords(ctx, msg)
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
	log.Info(ctx).Msg("refreshing directory users")

	ctx, clearTimeout := context.WithTimeout(ctx, mgr.cfg.Load().groupRefreshTimeout)
	defer clearTimeout()

	directoryGroups, directoryUsers, err := mgr.cfg.Load().directory.UserGroups(ctx)
	if err != nil {
		msg := "failed to refresh directory users and groups"
		if ctx.Err() != nil {
			msg += ". You may need to increase the identity provider directory timeout setting"
			msg += "(https://www.pomerium.io/reference/#identity-provider-refresh-directory-settings)"
		}
		log.Warn(ctx).Err(err).Msg(msg)
		return
	}

	mgr.mergeGroups(ctx, directoryGroups)
	mgr.mergeUsers(ctx, directoryUsers)

	metrics.RecordIdentityManagerLastRefresh()
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
			any, err := anypb.New(newDG)
			if err != nil {
				log.Warn(ctx).Err(err).Msg("failed to marshal directory group")
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
			any, err := anypb.New(curDG)
			if err != nil {
				log.Warn(ctx).Err(err).Msg("failed to marshal directory group")
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

	if err := eg.Wait(); err != nil {
		log.Warn(ctx).Err(err).Msg("manager: failed to merge groups")
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
			any, err := anypb.New(newDU)
			if err != nil {
				log.Warn(ctx).Err(err).Msg("failed to marshal directory user")
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
			any, err := anypb.New(curDU)
			if err != nil {
				log.Warn(ctx).Err(err).Msg("failed to marshal directory user")
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
		log.Warn(ctx).Err(err).Msg("manager: failed to merge users")
	}
}

func (mgr *Manager) refreshSession(ctx context.Context, userID, sessionID string) {
	log.Info(ctx).
		Str("user_id", userID).
		Str("session_id", sessionID).
		Msg("refreshing session")

	s, ok := mgr.sessions.Get(userID, sessionID)
	if !ok {
		log.Warn(ctx).
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session found for refresh")
		return
	}

	expiry := s.GetExpiresAt().AsTime()
	if !expiry.After(time.Now()) {
		log.Info(ctx).
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("deleting expired session")
		mgr.deleteSession(ctx, s.Session)
		return
	}

	if s.Session == nil || s.Session.OauthToken == nil {
		log.Warn(ctx).
			Str("user_id", userID).
			Str("session_id", sessionID).
			Msg("no session oauth2 token found for refresh")
		return
	}

	newToken, err := mgr.cfg.Load().authenticator.Refresh(ctx, FromOAuthToken(s.OauthToken), &s)
	if isTemporaryError(err) {
		log.Error(ctx).Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token")
		return
	} else if err != nil {
		log.Error(ctx).Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to refresh oauth2 token, deleting session")
		mgr.deleteSession(ctx, s.Session)
		return
	}
	s.OauthToken = ToOAuthToken(newToken)

	err = mgr.cfg.Load().authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), &s)
	if isTemporaryError(err) {
		log.Error(ctx).Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update user info")
		return
	} else if err != nil {
		log.Error(ctx).Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update user info, deleting session")
		mgr.deleteSession(ctx, s.Session)
		return
	}

	res, err := session.Put(ctx, mgr.cfg.Load().dataBrokerClient, s.Session)
	if err != nil {
		log.Error(ctx).Err(err).
			Str("user_id", s.GetUserId()).
			Str("session_id", s.GetId()).
			Msg("failed to update session")
		return
	}

	mgr.onUpdateSession(ctx, res.GetRecord(), s.Session)
}

func (mgr *Manager) refreshUser(ctx context.Context, userID string) {
	log.Info(ctx).
		Str("user_id", userID).
		Msg("refreshing user")

	u, ok := mgr.users.Get(userID)
	if !ok {
		log.Warn(ctx).
			Str("user_id", userID).
			Msg("no user found for refresh")
		return
	}
	u.lastRefresh = time.Now()
	mgr.userScheduler.Add(u.NextRefresh(), u.GetId())

	for _, s := range mgr.sessions.GetSessionsForUser(userID) {
		if s.Session == nil || s.Session.OauthToken == nil {
			log.Warn(ctx).
				Str("user_id", userID).
				Msg("no session oauth2 token found for refresh")
			continue
		}

		err := mgr.cfg.Load().authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), &u)
		if isTemporaryError(err) {
			log.Error(ctx).Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user info")
			return
		} else if err != nil {
			log.Error(ctx).Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user info, deleting session")
			mgr.deleteSession(ctx, s.Session)
			continue
		}

		record, err := user.Put(ctx, mgr.cfg.Load().dataBrokerClient, u.User)
		if err != nil {
			log.Error(ctx).Err(err).
				Str("user_id", s.GetUserId()).
				Str("session_id", s.GetId()).
				Msg("failed to update user")
			continue
		}

		mgr.onUpdateUser(ctx, record, u.User)
	}
}

func (mgr *Manager) onUpdateRecords(ctx context.Context, msg updateRecordsMessage) {
	for _, record := range msg.records {
		switch record.GetType() {
		case grpcutil.GetTypeURL(new(directory.Group)):
			var pbDirectoryGroup directory.Group
			err := record.GetData().UnmarshalTo(&pbDirectoryGroup)
			if err != nil {
				log.Warn(ctx).Msgf("error unmarshaling directory group: %s", err)
				continue
			}
			mgr.onUpdateDirectoryGroup(ctx, &pbDirectoryGroup)
		case grpcutil.GetTypeURL(new(directory.User)):
			var pbDirectoryUser directory.User
			err := record.GetData().UnmarshalTo(&pbDirectoryUser)
			if err != nil {
				log.Warn(ctx).Msgf("error unmarshaling directory user: %s", err)
				continue
			}
			mgr.onUpdateDirectoryUser(ctx, &pbDirectoryUser)
		case grpcutil.GetTypeURL(new(session.Session)):
			var pbSession session.Session
			err := record.GetData().UnmarshalTo(&pbSession)
			if err != nil {
				log.Warn(ctx).Msgf("error unmarshaling session: %s", err)
				continue
			}
			mgr.onUpdateSession(ctx, record, &pbSession)
		case grpcutil.GetTypeURL(new(user.User)):
			var pbUser user.User
			err := record.GetData().UnmarshalTo(&pbUser)
			if err != nil {
				log.Warn(ctx).Msgf("error unmarshaling user: %s", err)
				continue
			}
		}
	}
}

func (mgr *Manager) onUpdateSession(_ context.Context, record *databroker.Record, session *session.Session) {
	mgr.sessionScheduler.Remove(toSessionSchedulerKey(session.GetUserId(), session.GetId()))

	if record.GetDeletedAt() != nil {
		mgr.sessions.Delete(session.GetUserId(), session.GetId())
		return
	}

	// update session
	s, _ := mgr.sessions.Get(session.GetUserId(), session.GetId())
	s.lastRefresh = time.Now()
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
	u.lastRefresh = time.Now()
	u.refreshInterval = mgr.cfg.Load().groupRefreshInterval
	u.User = user
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
		log.Error(ctx).Err(err).
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
