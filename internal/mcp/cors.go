package mcp

import "net/http"

// SetCORSHeaders sets the CORS headers required for browser-based MCP clients
// (such as MCP Inspector) to interact with Pomerium-protected MCP server routes.
//
// This is used by the authorize service to add CORS headers to denied responses
// (401/403) and OPTIONS preflight responses at the Envoy ext_authz layer,
// before requests reach the Go HTTP handler's own CORS middleware.
func SetCORSHeaders(dst http.Header) {
	dst.Set("Access-Control-Allow-Origin", "*")
	dst.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	dst.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID")
	dst.Set("Access-Control-Expose-Headers", "WWW-Authenticate, MCP-Session-Id")
}
