package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

var (
	// ErrLifetimeExpired is an error for the lifetime deadline expiring
	ErrLifetimeExpired = errors.New("user lifetime expired")
)

// SessionState is our object that keeps track of a user's session state
type SessionState struct {
	AccessToken     string    `json:"access_token"`
	RefreshToken    string    `json:"refresh_token"`
	IDToken         string    `json:"id_token"`
	RefreshDeadline time.Time `json:"refresh_deadline"`

	Email  string   `json:"email"`
	User   string   `json:"user"`
	Groups []string `json:"groups"`

	ImpersonateEmail  string
	ImpersonateGroups []string
}

// RefreshPeriodExpired returns true if the refresh period has expired
func (s *SessionState) RefreshPeriodExpired() bool {
	return isExpired(s.RefreshDeadline)
}

type idToken struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Expiry   jsonTime `json:"exp"`
	IssuedAt jsonTime `json:"iat"`
	Nonce    string   `json:"nonce"`
	AtHash   string   `json:"at_hash"`
}

// IssuedAt parses the IDToken's issue date and returns a valid go time.Time.
func (s *SessionState) IssuedAt() (time.Time, error) {
	payload, err := parseJWT(s.IDToken)
	if err != nil {
		return time.Time{}, fmt.Errorf("internal/sessions: malformed jwt: %v", err)
	}
	var token idToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return time.Time{}, fmt.Errorf("internal/sessions: failed to unmarshal claims: %v", err)
	}
	return time.Time(token.IssuedAt), nil
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

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("internal/sessions: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("internal/sessions: malformed jwt payload: %v", err)
	}
	return payload, nil
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}
