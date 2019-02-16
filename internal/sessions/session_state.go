package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

var (
	// ErrLifetimeExpired is an error for the lifetime deadline expiring
	ErrLifetimeExpired = errors.New("user lifetime expired")
)

// SessionState is our object that keeps track of a user's session state
type SessionState struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`

	RefreshDeadline  time.Time `json:"refresh_deadline"`
	LifetimeDeadline time.Time `json:"lifetime_deadline"`

	Email  string   `json:"email"`
	User   string   `json:"user"` // 'sub' in jwt
	Groups []string `json:"groups"`
}

// LifetimePeriodExpired returns true if the lifetime has expired
func (s *SessionState) LifetimePeriodExpired() bool {
	return isExpired(s.LifetimeDeadline)
}

// RefreshPeriodExpired returns true if the refresh period has expired
func (s *SessionState) RefreshPeriodExpired() bool {
	return isExpired(s.RefreshDeadline)
}

func isExpired(t time.Time) bool {
	return t.Before(time.Now())
}

// MarshalSession marshals the session state as JSON, encrypts the JSON using the
// given cipher, and base64-encodes the result
func MarshalSession(s *SessionState, c cryptutil.Cipher) (string, error) {
	return c.Marshal(s)
}

// UnmarshalSession takes the marshaled string, base64-decodes into a byte slice, decrypts the
// byte slice using the passed cipher, and unmarshals the resulting JSON into a session state struct
func UnmarshalSession(value string, c cryptutil.Cipher) (*SessionState, error) {
	s := &SessionState{}
	err := c.Unmarshal(value, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ExtendDeadline returns the time extended by a given duration, truncated by second
func ExtendDeadline(ttl time.Duration) time.Time {
	return time.Now().Add(ttl).Truncate(time.Second)
}
