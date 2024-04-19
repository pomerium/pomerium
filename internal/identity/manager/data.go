package manager

import (
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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

	if s.GetExpiresAt() != nil {
		expiry := s.GetExpiresAt().AsTime()
		if s.GetExpiresAt().IsValid() && !expiry.IsZero() {
			if tm.IsZero() || expiry.Before(tm) {
				tm = expiry
			}
		}
	}

	// don't refresh any quicker than the cool-off duration
	min := lastRefresh.Add(coolOffDuration)
	if tm.Before(min) {
		tm = min
	}

	return tm
}

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

	if dst.Session.IdToken == nil {
		dst.Session.IdToken = new(session.IDToken)
	}

	if iss, ok := raw["iss"]; ok {
		_ = json.Unmarshal(iss, &dst.Session.IdToken.Issuer)
		delete(raw, "iss")
	}
	if sub, ok := raw["sub"]; ok {
		_ = json.Unmarshal(sub, &dst.Session.IdToken.Subject)
		delete(raw, "sub")
	}
	if exp, ok := raw["exp"]; ok {
		var secs int64
		if err := json.Unmarshal(exp, &secs); err == nil {
			dst.Session.IdToken.ExpiresAt = timestamppb.New(time.Unix(secs, 0))
		}
		delete(raw, "exp")
	}
	if iat, ok := raw["iat"]; ok {
		var secs int64
		if err := json.Unmarshal(iat, &secs); err == nil {
			dst.Session.IdToken.IssuedAt = timestamppb.New(time.Unix(secs, 0))
		}
		delete(raw, "iat")
	}

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
