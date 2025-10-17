package sessions

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
)

// ErrMissingID is the error for a session handle that has no ID set.
var ErrMissingID = errors.New("invalid session: missing id")

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

// Handle is a reference to a user session.
type Handle struct {
	// Public claim values (as specified in RFC 7519).
	Issuer   string           `json:"iss,omitempty"`
	Subject  string           `json:"sub,omitempty"`
	Audience jwt.Audience     `json:"aud,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
	ID       string           `json:"jti,omitempty"`

	// Azure returns OID which should be used instead of subject.
	OID string `json:"oid,omitempty"`

	// DatabrokerServerVersion tracks the last referenced databroker server version
	// for the saved session.
	DatabrokerServerVersion uint64 `json:"databroker_server_version,omitempty"`
	// DatabrokerRecordVersion tracks the last referenced databroker record version
	// for the saved session.
	DatabrokerRecordVersion uint64 `json:"databroker_record_version,omitempty"`

	// IdentityProviderID is the identity provider for the session.
	IdentityProviderID string `json:"idp_id,omitempty"`
}

// NewHandle creates a new Handle.
func NewHandle(idpID string) *Handle {
	return &Handle{
		IssuedAt:           jwt.NewNumericDate(timeNow()),
		ID:                 uuid.NewString(),
		IdentityProviderID: idpID,
	}
}

// WithNewIssuer creates a new Handle from an existing Handle.
func (h *Handle) WithNewIssuer(issuer string, audience []string) Handle {
	nh := Handle{}
	if h != nil {
		nh = *h
	}
	nh.IssuedAt = jwt.NewNumericDate(timeNow())
	nh.Audience = audience
	nh.Issuer = issuer
	return nh
}

// UserID returns the corresponding user ID for a session.
func (h *Handle) UserID() string {
	if h.OID != "" {
		return h.OID
	}
	return h.Subject
}

// UnmarshalJSON fills Handle struct from JSON. Additionally it munges
// a user's session by using by setting `user` claim to `sub` if empty.
func (h *Handle) UnmarshalJSON(data []byte) error {
	type HandleAlias Handle
	a := &struct {
		*HandleAlias
	}{
		HandleAlias: (*HandleAlias)(h),
	}

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	if h.ID == "" {
		return ErrMissingID
	}

	return nil
}
