package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

// DefaultBearerTokenHeader is default header name for the authorization bearer
// token header as defined in rfc2617
// https://tools.ietf.org/html/rfc6750#section-2.1
const DefaultBearerTokenHeader = "Authorization"

// RestStore is a session store suitable for REST
type RestStore struct {
	Name   string
	Cipher cryptutil.Cipher
	// Expire time.Duration
}

// RestStoreOptions contains the options required to build a new RestStore.
type RestStoreOptions struct {
	Name   string
	Cipher cryptutil.Cipher
	// Expire time.Duration
}

// NewRestStore creates a new RestStore from a set of RestStoreOptions.
func NewRestStore(opts *RestStoreOptions) (*RestStore, error) {
	if opts.Name == "" {
		opts.Name = DefaultBearerTokenHeader
	}
	if opts.Cipher == nil {
		return nil, fmt.Errorf("internal/sessions: cipher cannot be nil")
	}
	return &RestStore{
		Name: opts.Name,
		// Expire: opts.Expire,
		Cipher: opts.Cipher,
	}, nil
}

// ClearSession functions differently because REST is stateless, we instead
// inform the client that this token is no longer valid.
// https://tools.ietf.org/html/rfc6750
func (s *RestStore) ClearSession(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	errMsg := `
	{
		"error": "invalid_token",
		"token_type": "Bearer",
		"error_description": "The token has expired."
	}`
	w.Write([]byte(errMsg))
}

// LoadSession attempts to load a pomerium session from a Bearer Token set
// in the authorization header.
func (s *RestStore) LoadSession(r *http.Request) (*SessionState, error) {
	authHeader := r.Header.Get(s.Name)
	split := strings.Split(authHeader, "Bearer")
	if authHeader == "" || len(split) != 2 {
		return nil, errors.New("internal/sessions: no bearer token header found")
	}
	token := strings.TrimSpace(split[1])
	session, err := UnmarshalSession(token, s.Cipher)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// RestStoreResponse is the JSON struct returned to the client.
type RestStoreResponse struct {
	// Token is the encrypted pomerium session that can be used to
	// programmatically authenticate with pomerium.
	Token string
	// In addition to the token, non-sensitive meta data is returned to help
	// the client manage token renewals.
	Expiry time.Time
}

// SaveSession returns an encrypted pomerium session as a JSON object with
// associated, non sensitive meta-data like
func (s *RestStore) SaveSession(w http.ResponseWriter, r *http.Request, sessionState *SessionState) error {
	encToken, err := MarshalSession(sessionState, s.Cipher)
	if err != nil {
		return err
	}
	jsonBytes, err := json.Marshal(
		&RestStoreResponse{
			Token:  encToken,
			Expiry: sessionState.RefreshDeadline,
		})
	if err != nil {
		return fmt.Errorf("internal/sessions: couldn't marshal token struct: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
	return nil
}
