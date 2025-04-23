package mcp

import (
	"net/http"
)

// Token handles the /token endpoint.
func (srv *Handler) Token(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
