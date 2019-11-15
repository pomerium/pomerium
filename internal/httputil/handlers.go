package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"net/http"
)

// HealthCheck is a simple healthcheck handler that responds to GET and HEAD
// http requests.
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write([]byte(http.StatusText(http.StatusOK)))
	}
}

// Redirect wraps the std libs's redirect method indicating that pomerium is
// the origin of the response.
func Redirect(w http.ResponseWriter, r *http.Request, url string, code int) {
	w.Header().Set(HeaderPomeriumResponse, "true")
	http.Redirect(w, r, url, code)
}
