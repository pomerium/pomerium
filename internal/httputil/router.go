package httputil

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/pomerium/csrf"
)

// NewRouter returns a new router instance.
func NewRouter() *mux.Router {
	return mux.NewRouter()
}

// CSRFFailureHandler sets a HTTP 403 Forbidden status and writes the
// CSRF failure reason to the response.
func CSRFFailureHandler(w http.ResponseWriter, r *http.Request) error {
	if err := csrf.FailureReason(r); err != nil {
		return NewError(http.StatusBadRequest, csrf.FailureReason(r))
	}
	return nil
}
