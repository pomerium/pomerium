package mcp

import "net/http"

// SetCORSHeaders sets the CORS headers required for browser-based MCP clients
// (such as MCP Inspector) to interact with Pomerium-protected MCP server routes.
//
// This is used by the authorize service to add CORS headers to denied responses
// (401/403) and OPTIONS preflight responses at the Envoy ext_authz layer,
// before requests reach the Go HTTP handler's own CORS middleware.
//
// This layer covers MCP upstream routes — not the OAuth endpoints in handler.go
// (which have their own rs/cors middleware). The method and header sets differ:
//   - Methods include DELETE because MCP Streamable HTTP uses DELETE to terminate sessions.
//   - Headers include MCP-Session-Id, Last-Event-ID, etc. because the upstream MCP
//     transport requires them; the OAuth handler only needs authorization/content-type.
//
// AllowedOrigins is "*" (without AllowCredentials) because this is a public OAuth
// authorization server supporting dynamic client registration (RFC 7591) — any
// browser-based client origin is a valid MCP client. OAuth 2.1 §3.2 says these
// endpoints should "support the necessary CORS headers to allow the responses to
// be visible to the application" without restricting origins.
//
// Spec references:
//   - OAuth 2.1 §3.2: token, registration, metadata endpoints SHOULD support CORS.
//   - MCP Transport spec: servers MUST validate Origin on incoming connections
//     (DNS rebinding protection on upstream, not CORS policy at the auth layer).
//   - RFC 9728 §5: WWW-Authenticate with resource_metadata must be exposed to
//     browser clients via Access-Control-Expose-Headers.
func SetCORSHeaders(dst http.Header) {
	dst.Set("Access-Control-Allow-Origin", "*")
	dst.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	dst.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID")
	dst.Set("Access-Control-Expose-Headers", "WWW-Authenticate, MCP-Session-Id")
	// Vary is set for cache-correctness even with wildcard origins, matching
	// the behavior of rs/cors middleware used in the OAuth and metadata handlers.
	dst.Set("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
}
