package mcp

import (
	"net/http"
)

// Authorize handles the /authorize endpoint.
func (srv *Handler) Authorize(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
