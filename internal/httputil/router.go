package httputil // import "github.com/pomerium/pomerium/internal/httputil"

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
func CSRFFailureHandler(w http.ResponseWriter, r *http.Request) {
	ErrorResponse(w, r, Error("CSRF Failure", http.StatusForbidden, csrf.FailureReason(r)))
}
