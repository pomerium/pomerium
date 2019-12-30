package queryparam // import "github.com/pomerium/pomerium/internal/sessions/queryparam"

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/sessions"
)

var _ sessions.SessionStore = &Store{}
var _ sessions.SessionLoader = &Store{}

const (
	defaultQueryParamKey = "pomerium_session"
)

// Store implements the load session store interface using http
// query strings / query parameters.
type Store struct {
	queryParamKey string
	encoder       encoding.Marshaler
	decoder       encoding.Unmarshaler
}

// NewStore returns a new query param store for loading sessions from
// query strings / query parameters.
//
// NOTA BENE: By default, most servers _DO_ log query params, the leaking or
// accidental logging of which should be considered a security issue.
func NewStore(enc encoding.MarshalUnmarshaler, qp string) *Store {
	if qp == "" {
		qp = defaultQueryParamKey
	}
	return &Store{
		queryParamKey: qp,
		encoder:       enc,
		decoder:       enc,
	}
}

// LoadSession tries to retrieve the token string from URL query parameters.
func (qp *Store) LoadSession(r *http.Request) (*sessions.State, error) {
	cipherText := r.URL.Query().Get(qp.queryParamKey)
	if cipherText == "" {
		return nil, sessions.ErrNoSessionFound
	}
	var session sessions.State
	if err := qp.decoder.Unmarshal([]byte(cipherText), &session); err != nil {
		return nil, sessions.ErrMalformed
	}
	return &session, nil
}

// ClearSession clears the session cookie from a request's query param key `pomerium_session`.
func (qp *Store) ClearSession(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	params.Del(qp.queryParamKey)
	r.URL.RawQuery = params.Encode()
}

// SaveSession sets a session to a request's query param key `pomerium_session`
func (qp *Store) SaveSession(w http.ResponseWriter, r *http.Request, x interface{}) error {
	data, err := qp.encoder.Marshal(x)
	if err != nil {
		return err
	}
	r.URL.Query().Get(qp.queryParamKey)
	params := r.URL.Query()
	params.Set(qp.queryParamKey, string(data))
	r.URL.RawQuery = params.Encode()
	return nil
}
