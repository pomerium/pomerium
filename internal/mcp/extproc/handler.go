package extproc

import (
	"context"
)

// UpstreamRequestHandler handles upstream token injection and response interception.
// The implementation lives in the mcp package, where it has access to Storage, HostInfo,
// and discovery functions.
type UpstreamRequestHandler interface {
	// GetUpstreamToken looks up a cached upstream token for the given route context and host.
	// Returns the bearer token string if found and valid, or empty string if no token is available.
	// May perform inline token refresh if the cached token is expired but a refresh token exists.
	GetUpstreamToken(ctx context.Context, routeCtx *RouteContext, host string) (string, error)

	// HandleUpstreamResponse processes a 401/403 response from upstream.
	// Returns an UpstreamAuthAction describing how to respond to the client,
	// or nil if the response should be passed through unmodified.
	HandleUpstreamResponse(ctx context.Context, routeCtx *RouteContext, host, originalURL string, statusCode int, wwwAuthenticate string) (*UpstreamAuthAction, error)
}

// UpstreamAuthAction describes the ext_proc response when upstream returns 401/403.
type UpstreamAuthAction struct {
	// WWWAuthenticate is the value for the WWW-Authenticate header in the 401 response.
	// Non-empty means "return 401 to client with this header."
	WWWAuthenticate string
}
