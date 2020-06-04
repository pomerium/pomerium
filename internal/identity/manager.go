package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"github.com/mitchellh/hashstructure"
	"golang.org/x/oauth2"
	"gopkg.in/tomb.v2"

	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/grpc/user"
	"github.com/pomerium/pomerium/internal/log"
)

// A Manager refreshes identity information using session and user data.
type Manager struct {
	cfg           *managerConfig
	authenticator Authenticator
	sessionClient session.SessionServiceClient
	userClient    user.UserServiceClient

	byID        *btree.BTree
	byTimestamp *btree.BTree
}

// NewManager creates a new identity manager.
func NewManager(
	authenticator Authenticator,
	sessionClient session.SessionServiceClient,
	userClient user.UserServiceClient,
	options ...ManagerOption,
) *Manager {
	mgr := &Manager{
		cfg:           newManagerConfig(options...),
		authenticator: authenticator,
		sessionClient: sessionClient,
		userClient:    userClient,

		byID:        btree.New(8),
		byTimestamp: btree.New(8),
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
	timer := time.NewTimer(maxDuration)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case session := <-updatedSession:
			mgr.updateByID(session.GetUserId(), session.GetId(), func(item *managerItem) {
				item.session = session
			})
		case user := <-updatedUser:
			mgr.updateByID(user.GetId(), "", func(item *managerItem) {
				item.user = user
			})
		case <-timer.C:
		}

		now := time.Now()

		for {
			item, ok := mgr.byTimestamp.DeleteMin().(managerItemByTimestamp)
			if !ok {
				timer.Reset(maxDuration)
				break
			}

			mgr.byID.Delete(managerItemByID(item))

			currentSessionHash, currentUserHash := getHash(item.session), getHash(item.user)

			item.managerItem = mgr.maybeRefreshSession(ctx, now, item.managerItem)
			if item.managerItem == nil {
				// session refresh failed, so drop
				continue
			}

			item.managerItem = mgr.maybeRefreshGroups(ctx, now, item.managerItem)
			if item.managerItem == nil {
				// group refresh failed, so drop
				continue
			}

			newSessionHash, newUserHash := getHash(item.session), getHash(item.user)

			if currentSessionHash != newSessionHash {
				mgr.saveSession(ctx, item.session)
			}

			if currentUserHash != newUserHash {
				mgr.saveUser(ctx, item.user)
			}

			// re-insert
			mgr.byID.ReplaceOrInsert(managerItemByID(item))
			mgr.byTimestamp.ReplaceOrInsert(item)
			timer.Reset(item.NextProcessingTime().Sub(now))

			break
		}
	}
}

func (mgr *Manager) maybeRefreshSession(ctx context.Context, now time.Time, item *managerItem) *managerItem {
	// if the session has expired, for a re-login
	if item.IsSessionExpired(now) {
		mgr.clearSession(ctx, item.session)
		return nil
	}

	if !item.NeedsSessionRefresh(now) {
		return item
	}

	currentToken := fromOAuthToken(item.session.GetOauthToken())
	newToken, err := mgr.authenticator.Refresh(ctx, currentToken, item)
	if err != nil {
		log.Warn().Err(err).
			Str("session_id", item.SessionID()).
			Str("user_id", item.UserID()).
			Msg("failed to refresh session")

		mgr.clearSession(ctx, item.session)
		return nil
	}

	item.session.OauthToken = toOAuthToken(newToken)

	return item
}

func (mgr *Manager) maybeRefreshGroups(ctx context.Context, now time.Time, item *managerItem) *managerItem {
	if !item.NeedsGroupRefresh(now) {
		return item
	}

	currentToken := fromOAuthToken(item.session.GetOauthToken())
	err := mgr.authenticator.UpdateUserInfo(ctx, currentToken, item)
	if err != nil {
		log.Warn().Err(err).
			Str("session_id", item.SessionID()).
			Str("user_id", item.UserID()).
			Msg("failed to refresh user groups")

		mgr.clearSession(ctx, item.session)

		return nil
	}

	return item
}

func (mgr *Manager) clearSession(ctx context.Context, s *session.Session) {
	// attempt to revoke the session so the user will be forced to log in again
	if s != nil && s.OauthToken != nil {
		currentToken := fromOAuthToken(s.GetOauthToken())
		err := mgr.authenticator.Revoke(ctx, currentToken)
		if err != nil {
			log.Warn().Err(err).
				Str("session_id", s.GetId()).
				Msg("failed to revoke session")
		}
	}

	if s != nil {
		_, err := mgr.sessionClient.Delete(ctx, &session.DeleteRequest{
			Id: s.GetId(),
		})
		if err != nil {
			log.Warn().Err(err).
				Str("session_id", s.GetId()).
				Msg("failed to delete session")
		}
	}
}

func (mgr *Manager) saveSession(ctx context.Context, s *session.Session) {
	_, err := mgr.sessionClient.Add(ctx, &session.AddRequest{
		Session: s,
	})
	if err != nil {
		log.Warn().Err(err).
			Str("session_id", s.GetId()).
			Msg("failed to update session")
	}
}

func (mgr *Manager) saveUser(ctx context.Context, u *user.User) {
	_, err := mgr.userClient.Add(ctx, &user.AddRequest{
		User: u,
	})
	if err != nil {
		log.Warn().Err(err).
			Str("user_id", u.GetId()).
			Msg("failed to update user")
	}
}

func (mgr *Manager) syncSessions(ctx context.Context, ch chan<- *session.Session) error {
	log.Info().Str("service", "manager").Msg("syncing sessions")
	client, err := mgr.sessionClient.Sync(ctx, &session.SyncRequest{})
	if err != nil {
		return fmt.Errorf("error syncing sessions: %w", err)
	}
	for {
		res, err := client.Recv()
		if err != nil {
			return fmt.Errorf("error receiving sessions: %w", err)
		}

		for _, session := range res.GetSessions() {
			log.Info().Str("service", "manager").Interface("session", session).Msg("session update")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- session:
			}
		}
	}
}

func (mgr *Manager) syncUsers(ctx context.Context, ch chan<- *user.User) error {
	log.Info().Str("service", "manager").Msg("syncing users")
	client, err := mgr.userClient.Sync(ctx, &user.SyncRequest{})
	if err != nil {
		return fmt.Errorf("error syncing users: %w", err)
	}
	for {
		res, err := client.Recv()
		if err != nil {
			return fmt.Errorf("error receiving users: %w", err)
		}

		for _, user := range res.GetUsers() {
			log.Info().Str("service", "manager").Interface("user", user).Msg("user update")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- user:
			}
		}
	}
}

func (mgr *Manager) updateByID(userID, sessionID string, f func(*managerItem)) {
	userIDKey := managerItemByID{
		managerItem: &managerItem{
			user: &user.User{Id: userID},
		},
	}

	var toUpdate []managerItemByID
	mgr.byID.AscendGreaterOrEqual(userIDKey, func(i btree.Item) bool {
		item := i.(managerItemByID)
		if item.UserID() != userID {
			return false
		}
		if sessionID == "" || item.SessionID() == "" {
			toUpdate = append(toUpdate, item)
		}
		return true
	})

	for _, item := range toUpdate {
		// remove so we can re-sort
		mgr.byID.Delete(item)
		mgr.byTimestamp.Delete(managerItemByTimestamp(item))
	}

	if len(toUpdate) == 0 {
		toUpdate = append(toUpdate, managerItemByID{
			managerItem: &managerItem{
				session: &session.Session{
					Id:     sessionID,
					UserId: userID,
				},
				user: &user.User{
					Id: userID,
				},
				sessionRefreshGracePeriod: mgr.cfg.sessionRefreshGracePeriod,
				groupRefreshInterval:      mgr.cfg.groupRefreshInterval,
			},
		})
	}

	for _, item := range toUpdate {
		f(item.managerItem)
		mgr.byID.ReplaceOrInsert(item)
		mgr.byTimestamp.ReplaceOrInsert(managerItemByTimestamp(item))
	}
}

func fromOAuthToken(token *session.OAuthToken) *oauth2.Token {
	expiry, _ := ptypes.Timestamp(token.GetExpiresAt())
	return &oauth2.Token{
		AccessToken:  token.GetAccessToken(),
		TokenType:    token.GetTokenType(),
		RefreshToken: token.GetRefreshToken(),
		Expiry:       expiry,
	}
}

func toOAuthToken(token *oauth2.Token) *session.OAuthToken {
	expiry, _ := ptypes.TimestampProto(token.Expiry)
	return &session.OAuthToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    expiry,
	}
}

func getHash(v interface{}) uint64 {
	if v == nil {
		return 0
	}
	h, _ := hashstructure.Hash(v, &hashstructure.HashOptions{
		Hasher: xxhash.New(),
	})
	return h
}
