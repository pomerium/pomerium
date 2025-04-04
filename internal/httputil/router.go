package httputil

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/ui"
)

// NewRouter returns a new router instance.
func NewRouter() *mux.Router {
	return mux.NewRouter()
}

// CSRFFailureHandler sets a HTTP 403 Forbidden status and writes the
// CSRF failure reason to the response.
func CSRFFailureHandler(_ http.ResponseWriter, r *http.Request) error {
	if err := csrf.FailureReason(r); err != nil {
		return NewError(http.StatusBadRequest, csrf.FailureReason(r))
	}
	return nil
}

// DashboardSubrouter returns the .pomerium sub router.
func DashboardSubrouter(parent *mux.Router) *mux.Router {
	r := parent.PathPrefix("/.pomerium").Subrouter()
	for _, fileName := range []string{
		"apple-touch-icon.png",
		"favicon-16x16.png",
		"favicon-32x32.png",
		"favicon.ico",
		"index.css",
		"index.js",
	} {
		r.Path("/" + fileName).Handler(HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return ui.ServeFile(w, r, fileName)
		}))
	}
	// return a new subrouter so any middleware doesn't get added to the static files
	return r.NewRoute().Subrouter()
}
