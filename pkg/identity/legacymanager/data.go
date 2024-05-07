package legacymanager

import (
	"encoding/json"
	"time"

	"github.com/google/btree"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
)

const userRefreshInterval = 10 * time.Minute

// A User is a user managed by the Manager.
type User struct {
	*user.User
	lastRefresh time.Time
}

// NextRefresh returns the next time the user information needs to be refreshed.
func (u User) NextRefresh() time.Time {
	return u.lastRefresh.Add(userRefreshInterval)
}

// UnmarshalJSON unmarshals json data into the user object.
func (u *User) UnmarshalJSON(data []byte) error {
	if u.User == nil {
		u.User = new(user.User)
	}

	var raw map[string]json.RawMessage
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	if name, ok := raw["name"]; ok {
		_ = json.Unmarshal(name, &u.User.Name)
		delete(raw, "name")
	}
	if email, ok := raw["email"]; ok {
		_ = json.Unmarshal(email, &u.User.Email)
		delete(raw, "email")
	}

	u.AddClaims(identity.NewClaimsFromRaw(raw).Flatten())

	return nil
}

// A Session is a session managed by the Manager.
type Session struct {
	*session.Session
	// lastRefresh is the time of the last refresh attempt (which may or may
	// not have succeeded), or else the time the Manager first became aware of
	// the session (if it has not yet attempted to refresh this session).
	lastRefresh time.Time
	// gracePeriod is the amount of time before expiration to attempt a refresh.
	gracePeriod time.Duration
	// coolOffDuration is the amount of time to wait before attempting another refresh.
	coolOffDuration time.Duration
}

// NextRefresh returns the next time the session needs to be refreshed.
func (s Session) NextRefresh() time.Time {
	var tm time.Time

	if s.GetOauthToken().GetExpiresAt() != nil {
		expiry := s.GetOauthToken().GetExpiresAt().AsTime()
		if s.GetOauthToken().GetExpiresAt().IsValid() && !expiry.IsZero() {
			expiry = expiry.Add(-s.gracePeriod)
			if tm.IsZero() || expiry.Before(tm) {
				tm = expiry
			}
		}
	}

	if s.GetExpiresAt() != nil {
		expiry := s.GetExpiresAt().AsTime()
		if s.GetExpiresAt().IsValid() && !expiry.IsZero() {
			if tm.IsZero() || expiry.Before(tm) {
				tm = expiry
			}
		}
	}

	// don't refresh any quicker than the cool-off duration
	min := s.lastRefresh.Add(s.coolOffDuration)
	if tm.Before(min) {
		tm = min
	}

	return tm
}

// UnmarshalJSON unmarshals json data into the session object.
func (s *Session) UnmarshalJSON(data []byte) error {
	if s.Session == nil {
		s.Session = new(session.Session)
	}

	var raw map[string]json.RawMessage
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	if s.Session.IdToken == nil {
		s.Session.IdToken = new(session.IDToken)
	}

	if iss, ok := raw["iss"]; ok {
		_ = json.Unmarshal(iss, &s.Session.IdToken.Issuer)
		delete(raw, "iss")
	}
	if sub, ok := raw["sub"]; ok {
		_ = json.Unmarshal(sub, &s.Session.IdToken.Subject)
		delete(raw, "sub")
	}
	if exp, ok := raw["exp"]; ok {
		var secs int64
		if err := json.Unmarshal(exp, &secs); err == nil {
			s.Session.IdToken.ExpiresAt = timestamppb.New(time.Unix(secs, 0))
		}
		delete(raw, "exp")
	}
	if iat, ok := raw["iat"]; ok {
		var secs int64
		if err := json.Unmarshal(iat, &secs); err == nil {
			s.Session.IdToken.IssuedAt = timestamppb.New(time.Unix(secs, 0))
		}
		delete(raw, "iat")
	}

	s.AddClaims(identity.NewClaimsFromRaw(raw).Flatten())

	return nil
}

type sessionCollectionItem struct {
	Session
}

func (item sessionCollectionItem) Less(than btree.Item) bool {
	xUserID, yUserID := item.GetUserId(), than.(sessionCollectionItem).GetUserId()
	switch {
	case xUserID < yUserID:
		return true
	case yUserID < xUserID:
		return false
	}

	xID, yID := item.GetId(), than.(sessionCollectionItem).GetId()
	switch {
	case xID < yID:
		return true
	case yID < xID:
		return false
	}
	return false
}

type sessionCollection struct {
	*btree.BTree
}

func (c *sessionCollection) Delete(userID, sessionID string) {
	c.BTree.Delete(sessionCollectionItem{
		Session: Session{
			Session: &session.Session{
				UserId: userID,
				Id:     sessionID,
			},
		},
	})
}

func (c *sessionCollection) Get(userID, sessionID string) (Session, bool) {
	item := c.BTree.Get(sessionCollectionItem{
		Session: Session{
			Session: &session.Session{
				UserId: userID,
				Id:     sessionID,
			},
		},
	})
	if item == nil {
		return Session{}, false
	}
	return item.(sessionCollectionItem).Session, true
}

// GetSessionsForUser gets all the sessions for the given user.
func (c *sessionCollection) GetSessionsForUser(userID string) []Session {
	var sessions []Session
	c.AscendGreaterOrEqual(sessionCollectionItem{
		Session: Session{
			Session: &session.Session{
				UserId: userID,
			},
		},
	}, func(item btree.Item) bool {
		s := item.(sessionCollectionItem).Session
		if s.UserId != userID {
			return false
		}

		sessions = append(sessions, s)
		return true
	})
	return sessions
}

func (c *sessionCollection) ReplaceOrInsert(s Session) {
	c.BTree.ReplaceOrInsert(sessionCollectionItem{Session: s})
}

type userCollectionItem struct {
	User
}

func (item userCollectionItem) Less(than btree.Item) bool {
	xID, yID := item.GetId(), than.(userCollectionItem).GetId()
	switch {
	case xID < yID:
		return true
	case yID < xID:
		return false
	}
	return false
}

type userCollection struct {
	*btree.BTree
}

func (c *userCollection) Delete(userID string) {
	c.BTree.Delete(userCollectionItem{
		User: User{
			User: &user.User{
				Id: userID,
			},
		},
	})
}

func (c *userCollection) Get(userID string) (User, bool) {
	item := c.BTree.Get(userCollectionItem{
		User: User{
			User: &user.User{
				Id: userID,
			},
		},
	})
	if item == nil {
		return User{}, false
	}
	return item.(userCollectionItem).User, true
}

func (c *userCollection) ReplaceOrInsert(u User) {
	c.BTree.ReplaceOrInsert(userCollectionItem{User: u})
}
