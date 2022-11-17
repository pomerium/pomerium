package handlers

import (
	"fmt"
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
		fmt.Fprintln(w, http.StatusText(http.StatusOK))
	}
}
