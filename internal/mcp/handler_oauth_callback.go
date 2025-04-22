package mcp

import (
	"net/http"
)

func (srv *Handler) OAuthCallback(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
