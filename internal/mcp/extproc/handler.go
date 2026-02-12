package extproc

import (
	"context"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
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

// injectAuthorizationHeader returns a ProcessingResponse that injects an Authorization header
// and continues the request to upstream.
func injectAuthorizationHeader(token string) *ext_proc_v3.ProcessingResponse {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &ext_proc_v3.HeadersResponse{
				Response: &ext_proc_v3.CommonResponse{
					Status: ext_proc_v3.CommonResponse_CONTINUE,
					HeaderMutation: &ext_proc_v3.HeaderMutation{
						SetHeaders: []*envoy_config_core_v3.HeaderValueOption{{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:      "authorization",
								RawValue: []byte("Bearer " + token),
							},
						}},
					},
				},
			},
		},
	}
}

// immediateUnauthorizedResponse returns a ProcessingResponse that sends an immediate 401
// to the client with the specified WWW-Authenticate header.
func immediateUnauthorizedResponse(wwwAuthenticate string) *ext_proc_v3.ProcessingResponse {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &ext_proc_v3.ImmediateResponse{
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode_Unauthorized,
				},
				Headers: &ext_proc_v3.HeaderMutation{
					SetHeaders: []*envoy_config_core_v3.HeaderValueOption{
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:      "www-authenticate",
								RawValue: []byte(wwwAuthenticate),
							},
						},
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:      "cache-control",
								RawValue: []byte("no-store"),
							},
						},
					},
				},
			},
		},
	}
}
