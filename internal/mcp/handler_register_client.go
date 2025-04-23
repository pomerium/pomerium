package mcp

import (
	"net/http"
)

// RegisterClient handles the /register endpoint.
// It is used to register a new client with the MCP server.
func (srv *Handler) RegisterClient(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
