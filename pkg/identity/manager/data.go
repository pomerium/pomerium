package manager

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
)

func nextSessionRefresh(
	s *session.Session,
	lastRefresh time.Time,
	gracePeriod time.Duration,
	coolOffDuration time.Duration,
) time.Time {
	var tm time.Time

	if s.GetOauthToken().GetExpiresAt() != nil {
		expiry := s.GetOauthToken().GetExpiresAt().AsTime()
		if s.GetOauthToken().GetExpiresAt().IsValid() && !expiry.IsZero() {
			expiry = expiry.Add(-gracePeriod)
			if tm.IsZero() || expiry.Before(tm) {
				tm = expiry
			}
		}
	}

	if s.GetIdToken().GetExpiresAt() != nil {
		expiry := s.GetIdToken().GetExpiresAt().AsTime()
		if s.GetIdToken().GetExpiresAt().IsValid() && !expiry.IsZero() {
			expiry = expiry.Add(-gracePeriod)
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
	v := lastRefresh.Add(coolOffDuration)
	if tm.Before(v) {
		tm = v
	}

	return tm
}

// a multiUnmarshaler is used as the target of the json Unmarshal function to
// unmarshal a single JSON value into multiple destinations.
type multiUnmarshaler []any

func newMultiUnmarshaler(args ...any) *multiUnmarshaler {
	return (*multiUnmarshaler)(&args)
}

func (dst *multiUnmarshaler) UnmarshalJSON(data []byte) error {
	var err error
	for _, o := range *dst {
		if o != nil {
			err = errors.Join(err, json.Unmarshal(data, o))
		}
	}
	return err
}

type sessionUnmarshaler struct {
	*session.Session
}

func newSessionUnmarshaler(s *session.Session) *sessionUnmarshaler {
	return &sessionUnmarshaler{Session: s}
}

func (dst *sessionUnmarshaler) UnmarshalJSON(data []byte) error {
	if dst.Session == nil {
		return nil
	}

	var raw map[string]json.RawMessage
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	// To preserve existing behavior: filter out claims not related to user info.
	delete(raw, "iss")
	delete(raw, "sub")
	delete(raw, "exp")
	delete(raw, "iat")

	dst.Session.AddClaims(identity.NewClaimsFromRaw(raw).Flatten())

	return nil
}

type userUnmarshaler struct {
	*user.User
}

func newUserUnmarshaler(u *user.User) *userUnmarshaler {
	return &userUnmarshaler{User: u}
}

func (dst *userUnmarshaler) UnmarshalJSON(data []byte) error {
	if dst.User == nil {
		return nil
	}

	var raw map[string]json.RawMessage
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	if name, ok := raw["name"]; ok {
		_ = json.Unmarshal(name, &dst.User.Name)
		delete(raw, "name")
	}
	if email, ok := raw["email"]; ok {
		_ = json.Unmarshal(email, &dst.User.Email)
		delete(raw, "email")
	}

	dst.User.AddClaims(identity.NewClaimsFromRaw(raw).Flatten())

	return nil
}
