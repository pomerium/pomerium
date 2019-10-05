package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

const (
	defaultQueryParamKey = "pomerium_session"
)

// QueryParamStore implements the load session store interface using http
// query strings / query parameters.
type QueryParamStore struct {
	queryParamKey string
	encoder       cryptutil.SecureEncoder
}

// NewQueryParamStore returns a new query param store for loading sessions from
// query strings / query parameters.
func NewQueryParamStore(enc cryptutil.SecureEncoder) *QueryParamStore {
	return &QueryParamStore{
		queryParamKey: defaultQueryParamKey,
		encoder:       enc,
	}
}

// LoadSession tries to retrieve the token string from URL query parameters.
//
// NOTA BENE: By default, most servers _DO_ log query params, the leaking or
// accidental logging of which should be considered a security issue.
func (qp *QueryParamStore) LoadSession(r *http.Request) (*State, error) {
	cipherText := r.URL.Query().Get(qp.queryParamKey)
	if cipherText == "" {
		return nil, ErrNoSessionFound
	}
	session, err := UnmarshalSession(cipherText, qp.encoder)
	if err != nil {
		return nil, ErrMalformed
	}
	return session, nil

}
