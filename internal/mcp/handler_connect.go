package mcp

import (
	"net/http"
)

// Connect is a helper method for MCP clients to ensure that the current user
// has an active upstream Oauth2 session for the route.
func (srv *Handler) Connect(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
