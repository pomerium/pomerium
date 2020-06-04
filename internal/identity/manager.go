package identity

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/tomb.v2"

	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/grpc/user"
	"github.com/pomerium/pomerium/internal/log"
)

var (
	maxTime     = time.Unix(1<<63-62135596801, 999999999)
	maxDuration = time.Duration(1<<63 - 1)
)

type managerConfig struct {
	groupRefreshInterval      time.Duration
	sessionRefreshGracePeriod time.Duration
}

func newManagerConfig(options ...ManagerOption) *managerConfig {
	cfg := new(managerConfig)
	WithGroupRefreshInterval(time.Minute * 10)(cfg)
	WithSessionRefreshGracePeriod(time.Second * 30)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A ManagerOption customizes the configuration used for the identity manager.
type ManagerOption func(*managerConfig)

// WithGroupRefreshInterval sets the group refresh interval used by the manager.
func WithGroupRefreshInterval(interval time.Duration) ManagerOption {
	return func(cfg *managerConfig) {
		cfg.groupRefreshInterval = interval
	}
}

// WithSessionRefreshGracePeriod sets the session refresh grace period used by the manager.
func WithSessionRefreshGracePeriod(gracePeriod time.Duration) ManagerOption {
	return func(cfg *managerConfig) {
		cfg.sessionRefreshGracePeriod = gracePeriod
	}
}

type managerItem struct {
	session          *session.Session
	user             *user.User
	lastGroupRefresh time.Time

	sessionRefreshGracePeriod, groupRefreshInterval time.Duration
}

func (item *managerItem) NeedsGroupRefresh(now time.Time) bool {
	if item == nil || item.session == nil || item.session.OauthToken == nil {
		return false
	}

	tm := item.lastGroupRefresh.Add(item.groupRefreshInterval)
	if tm.After(now) {
		return false
	}

	return true
}

func (item *managerItem) NeedsSessionRefresh(now time.Time) bool {
	if item == nil || item.session == nil {
		return false
	}
	tm, err := ptypes.Timestamp(item.session.GetExpiresAt())
	if err != nil {
		return false
	}
	tm = tm.Add(-item.sessionRefreshGracePeriod)
	if tm.After(now) {
		return false
	}
	return true
}

func (item *managerItem) NextProcessingTime() time.Time {
	min := maxTime

	if item != nil {
		min = item.lastGroupRefresh.Add(item.groupRefreshInterval)

		if item.session != nil {
			expires, err := ptypes.Timestamp(item.session.GetExpiresAt())
			if err == nil {
				expires = expires.Add(-item.sessionRefreshGracePeriod)
				if expires.Before(min) {
					min = expires
				}
			}
		}
	}

	return min
}

func (item *managerItem) SessionID() string {
	if item.session == nil {
		return ""
	}
	return item.session.GetId()
}

func (item *managerItem) UserID() string {
	if item.user == nil {
		return ""
	}
	return item.user.GetId()
}

type managerItemByTimestamp struct {
	*managerItem
}

func (item managerItemByTimestamp) Less(than btree.Item) bool {
	x := item
	y := than.(managerItemByTimestamp)

	xtm := x.NextProcessingTime()
	ytm := y.NextProcessingTime()

	// first sort by timestamp
	switch {
	case xtm.Before(ytm):
		return true
	case ytm.Before(xtm):
		return false
	}

	// fallback to sorting by (user_id, session_id)
	return managerItemByID(x).Less(managerItemByID(y))
}

type managerItemByID struct {
	*managerItem
}

func (item managerItemByID) Less(than btree.Item) bool {
	x := item
	y := than.(managerItemByID)

	switch {
	case x.UserID() < y.UserID():
		return true
	case y.UserID() < x.UserID():
		return false
	}

	switch {
	case x.SessionID() < y.SessionID():
		return true
	case y.SessionID() < x.SessionID():
		return false
	}

	return false
}

// A Manager refreshes identity information using session and user data.
type Manager struct {
	cfg           *managerConfig
	authenticator Authenticator
	sessionClient session.SessionServiceClient
	userClient    user.UserServiceClient

	closeOnce sync.Once
	closed    chan struct{}

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

		closed: make(chan struct{}),

		byID:        btree.New(8),
		byTimestamp: btree.New(8),
	}
	return mgr
}

// Run runs the manager. This method blocks until an error occurs or the given context is cancelled.
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

			// re-insert
			mgr.byID.ReplaceOrInsert(managerItemByID(item))
			mgr.byTimestamp.ReplaceOrInsert(managerItemByTimestamp(item))
			timer.Reset(item.NextProcessingTime().Sub(now))

			break
		}
	}
}

func (mgr *Manager) maybeRefreshSession(ctx context.Context, now time.Time, item *managerItem) *managerItem {
	if !item.NeedsSessionRefresh(now) {
		return item
	}

	currentToken := fromOAuthToken(item.session.GetOauthToken())
	newToken, err := mgr.authenticator.Refresh(ctx, currentToken, item.session.IDTokenJSONFiller())
	if err != nil {
		log.Warn().Err(err).
			Str("id", item.SessionID()).
			Msg("failed to refresh session")

		// attempt to revoke the session so the user will be forced to log in again
		err = mgr.authenticator.Revoke(ctx, currentToken)
		if err != nil {
			log.Warn().Err(err).
				Str("id", item.SessionID()).
				Msg("failed to revoke session")
		}

		_, err = mgr.sessionClient.Delete(ctx, &session.DeleteRequest{
			Id: item.SessionID(),
		})
		if err != nil {
			log.Warn().Err(err).
				Str("id", item.SessionID()).
				Msg("failed to delete session")
		}

		return nil
	}

	item.session.OauthToken = toOAuthToken(newToken)
	_, err = mgr.sessionClient.Add(ctx, &session.AddRequest{
		Session: item.session,
	})
	if err != nil {
		log.Warn().Err(err).
			Str("id", item.SessionID()).
			Msg("failed to update session")
		return nil
	}

	return item
}

func (mgr *Manager) maybeRefreshGroups(ctx context.Context, now time.Time, item *managerItem) *managerItem {
	if !item.NeedsGroupRefresh(now) {
		return item
	}

	currentToken := fromOAuthToken(item.session.GetOauthToken())
	err := mgr.authenticator.UpdateUserInfo(ctx, currentToken, nil)
	if err != nil {
		log.Warn().Err(err).
			Str("session_id", item.SessionID()).
			Str("user_id", item.UserID()).
			Msg("failed to refresh user groups")

		// attempt to revoke the session so the user will be forced to log in again
		err = mgr.authenticator.Revoke(ctx, currentToken)
		if err != nil {
			log.Warn().Err(err).
				Str("session_id", item.SessionID()).
				Str("user_id", item.UserID()).
				Msg("failed to revoke session")
		}

		_, err = mgr.sessionClient.Delete(ctx, &session.DeleteRequest{
			Id: item.SessionID(),
		})
		if err != nil {
			log.Warn().Err(err).
				Str("session_id", item.SessionID()).
				Str("user_id", item.UserID()).
				Msg("failed to delete session")
		}

		return nil
	}

	_, err = mgr.userClient.Add(ctx, &user.AddRequest{
		User: item.user,
	})
	if err != nil {
		log.Warn().Err(err).
			Str("session_id", item.SessionID()).
			Str("user_id", item.UserID()).
			Msg("failed to update user")
		return nil
	}

	return item
}

func (mgr *Manager) syncSessions(ctx context.Context, ch chan<- *session.Session) error {
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
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- session:
			}
		}
	}
}

func (mgr *Manager) syncUsers(ctx context.Context, ch chan<- *user.User) error {
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

func minTimestamp(ts ...*timestamppb.Timestamp) time.Time {
	var min time.Time
	for _, t := range ts {
		tm, _ := ptypes.Timestamp(t)
		if tm.IsZero() {
			continue
		}
		if min.IsZero() || tm.Before(min) {
			min = tm
		}
	}
	return min
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
