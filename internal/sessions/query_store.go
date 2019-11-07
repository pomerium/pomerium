package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"
)

const (
	defaultQueryParamKey = "pomerium_session"
)

// QueryParamStore implements the load session store interface using http
// query strings / query parameters.
type QueryParamStore struct {
	queryParamKey string
	encoder       Marshaler
	decoder       Unmarshaler
}

// NewQueryParamStore returns a new query param store for loading sessions from
// query strings / query parameters.
//
// NOTA BENE: By default, most servers _DO_ log query params, the leaking or
// accidental logging of which should be considered a security issue.
func NewQueryParamStore(enc Encoder, qp string) *QueryParamStore {
	if qp == "" {
		qp = defaultQueryParamKey
	}
	return &QueryParamStore{
		queryParamKey: qp,
		encoder:       enc,
		decoder:       enc,
	}
}

// LoadSession tries to retrieve the token string from URL query parameters.
func (qp *QueryParamStore) LoadSession(r *http.Request) (*State, error) {
	cipherText := r.URL.Query().Get(qp.queryParamKey)
	if cipherText == "" {
		return nil, ErrNoSessionFound
	}
	var session State
	if err := qp.decoder.Unmarshal([]byte(cipherText), &session); err != nil {
		return nil, ErrMalformed
	}
	return &session, nil
}

// ClearSession clears the session cookie from a request's query param key `pomerium_session`.
func (qp *QueryParamStore) ClearSession(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	params.Del(qp.queryParamKey)
	r.URL.RawQuery = params.Encode()
}

// SaveSession sets a session to a request's query param key `pomerium_session`
func (qp *QueryParamStore) SaveSession(w http.ResponseWriter, r *http.Request, x interface{}) error {
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
