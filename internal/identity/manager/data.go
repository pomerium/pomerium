package manager

import (
	"encoding/json"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/grpc/user"
)

// A User is a user managed by the Manager.
type User struct {
	*user.User
	lastRefresh     time.Time
	refreshInterval time.Duration
}

// NextRefresh returns the next time the user information needs to be refreshed.
func (u User) NextRefresh() time.Time {
	return u.lastRefresh.Add(u.refreshInterval)
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

	u.User.Claims = make(map[string]*anypb.Any)
	for k, rawv := range raw {
		var v interface{}
		if json.Unmarshal(rawv, &v) != nil {
			continue
		}

		if anyv, err := toAny(v); err == nil {
			u.User.Claims[k] = anyv
		}
	}

	return nil
}

// A Session is a session managed by the Manager.
type Session struct {
	*session.Session
	lastRefresh time.Time
	// gracePeriod is the amount of time before expiration to attempt a refresh.
	gracePeriod time.Duration
	// coolOffDuration is the amount of time to wait before attempting another refresh.
	coolOffDuration time.Duration
}

// NextRefresh returns the next time the session needs to be refreshed.
func (s Session) NextRefresh() time.Time {
	var tm time.Time

	expiry, err := ptypes.Timestamp(s.GetOauthToken().GetExpiresAt())
	if err == nil {
		expiry = expiry.Add(-s.gracePeriod)
		if tm.IsZero() || expiry.Before(tm) {
			tm = expiry
		}
	}

	expiry, err = ptypes.Timestamp(s.GetIdToken().GetExpiresAt())
	if err == nil {
		expiry = expiry.Add(-s.gracePeriod)
		if tm.IsZero() || expiry.Before(tm) {
			tm = expiry
		}
	}

	expiry, err = ptypes.Timestamp(s.GetExpiresAt())
	if err == nil {
		if tm.IsZero() || expiry.Before(tm) {
			tm = expiry
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
			s.Session.IdToken.ExpiresAt, _ = ptypes.TimestampProto(time.Unix(secs, 0))
		}
		delete(raw, "exp")
	}
	if iat, ok := raw["iat"]; ok {
		var secs int64
		if err := json.Unmarshal(iat, &secs); err == nil {
			s.Session.IdToken.IssuedAt, _ = ptypes.TimestampProto(time.Unix(secs, 0))
		}
		delete(raw, "iat")
	}

	s.Session.Claims = make(map[string]*anypb.Any)
	for k, rawv := range raw {
		var v interface{}
		if json.Unmarshal(rawv, &v) != nil {
			continue
		}

		if anyv, err := toAny(v); err == nil {
			s.Session.Claims[k] = anyv
		}
	}

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
