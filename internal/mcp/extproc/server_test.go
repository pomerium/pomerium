package extproc

import (
	"context"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestExtractRouteContext(t *testing.T) {
	t.Parallel()

	s := &Server{}

	t.Run("nil metadata returns nil", func(t *testing.T) {
		result := s.extractRouteContext(nil)
		assert.Nil(t, result)
	})

	t.Run("empty metadata returns nil", func(t *testing.T) {
		metadata := &envoy_config_core_v3.Metadata{}
		result := s.extractRouteContext(metadata)
		assert.Nil(t, result)
	})

	t.Run("missing ext_authz namespace returns nil", func(t *testing.T) {
		metadata := &envoy_config_core_v3.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				"some.other.namespace": {},
			},
		}
		result := s.extractRouteContext(metadata)
		assert.Nil(t, result)
	})

	t.Run("missing route-context in ext_authz returns nil", func(t *testing.T) {
		metadata := &envoy_config_core_v3.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				ExtAuthzMetadataNamespace: {
					Fields: map[string]*structpb.Value{
						"other_key": structpb.NewStringValue("value"),
					},
				},
			},
		}
		result := s.extractRouteContext(metadata)
		assert.Nil(t, result)
	})

	t.Run("extracts route context successfully", func(t *testing.T) {
		metadata := &envoy_config_core_v3.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				ExtAuthzMetadataNamespace: {
					Fields: map[string]*structpb.Value{
						RouteContextMetadataNamespace: {
							Kind: &structpb.Value_StructValue{
								StructValue: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"route_id":   structpb.NewStringValue("route-123"),
										"session_id": structpb.NewStringValue("session-456"),
										"is_mcp":     structpb.NewBoolValue(true),
									},
								},
							},
						},
					},
				},
			},
		}

		result := s.extractRouteContext(metadata)

		require.NotNil(t, result)
		assert.Equal(t, "route-123", result.RouteID)
		assert.Equal(t, "session-456", result.SessionID)
		assert.True(t, result.IsMCP)
	})

	t.Run("handles missing fields gracefully", func(t *testing.T) {
		metadata := &envoy_config_core_v3.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				ExtAuthzMetadataNamespace: {
					Fields: map[string]*structpb.Value{
						RouteContextMetadataNamespace: {
							Kind: &structpb.Value_StructValue{
								StructValue: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"route_id": structpb.NewStringValue("route-only"),
										// session_id and is_mcp are missing
									},
								},
							},
						},
					},
				},
			},
		}

		result := s.extractRouteContext(metadata)

		require.NotNil(t, result)
		assert.Equal(t, "route-only", result.RouteID)
		assert.Empty(t, result.SessionID)
		assert.False(t, result.IsMCP)
	})
}

func TestGetHeaderValue(t *testing.T) {
	t.Parallel()

	t.Run("nil headers returns empty", func(t *testing.T) {
		result := getHeaderValue(nil, ":status")
		assert.Empty(t, result)
	})

	t.Run("empty headers returns empty", func(t *testing.T) {
		headers := &envoy_config_core_v3.HeaderMap{}
		result := getHeaderValue(headers, ":status")
		assert.Empty(t, result)
	})

	t.Run("missing header returns empty", func(t *testing.T) {
		headers := &envoy_config_core_v3.HeaderMap{
			Headers: []*envoy_config_core_v3.HeaderValue{
				{Key: ":method", Value: "GET"},
			},
		}
		result := getHeaderValue(headers, ":status")
		assert.Empty(t, result)
	})

	t.Run("finds header value", func(t *testing.T) {
		headers := &envoy_config_core_v3.HeaderMap{
			Headers: []*envoy_config_core_v3.HeaderValue{
				{Key: ":method", Value: "POST"},
				{Key: ":status", Value: "200"},
				{Key: ":path", Value: "/api/v1"},
			},
		}
		result := getHeaderValue(headers, ":status")
		assert.Equal(t, "200", result)
	})

	t.Run("returns first match for duplicate headers", func(t *testing.T) {
		headers := &envoy_config_core_v3.HeaderMap{
			Headers: []*envoy_config_core_v3.HeaderValue{
				{Key: "x-custom", Value: "first"},
				{Key: "x-custom", Value: "second"},
			},
		}
		result := getHeaderValue(headers, "x-custom")
		assert.Equal(t, "first", result)
	})
}

func TestContinueResponses(t *testing.T) {
	t.Parallel()

	t.Run("request headers response has correct type", func(t *testing.T) {
		resp := continueRequestHeadersResponse()
		require.NotNil(t, resp)

		_, ok := resp.Response.(*ext_proc_v3.ProcessingResponse_RequestHeaders)
		assert.True(t, ok, "expected RequestHeaders response type")

		reqHeaders := resp.GetRequestHeaders()
		require.NotNil(t, reqHeaders)
		assert.Equal(t, ext_proc_v3.CommonResponse_CONTINUE, reqHeaders.Response.Status)
	})

	t.Run("response headers response has correct type", func(t *testing.T) {
		resp := continueResponseHeadersResponse()
		require.NotNil(t, resp)

		_, ok := resp.Response.(*ext_proc_v3.ProcessingResponse_ResponseHeaders)
		assert.True(t, ok, "expected ResponseHeaders response type")

		respHeaders := resp.GetResponseHeaders()
		require.NotNil(t, respHeaders)
		assert.Equal(t, ext_proc_v3.CommonResponse_CONTINUE, respHeaders.Response.Status)
	})

	t.Run("request body response has correct type", func(t *testing.T) {
		resp := continueRequestBodyResponse()
		require.NotNil(t, resp)

		_, ok := resp.Response.(*ext_proc_v3.ProcessingResponse_RequestBody)
		assert.True(t, ok, "expected RequestBody response type")
	})

	t.Run("response body response has correct type", func(t *testing.T) {
		resp := continueResponseBodyResponse()
		require.NotNil(t, resp)

		_, ok := resp.Response.(*ext_proc_v3.ProcessingResponse_ResponseBody)
		assert.True(t, ok, "expected ResponseBody response type")
	})

	t.Run("request trailers response has correct type", func(t *testing.T) {
		resp := continueRequestTrailersResponse()
		require.NotNil(t, resp)

		_, ok := resp.Response.(*ext_proc_v3.ProcessingResponse_RequestTrailers)
		assert.True(t, ok, "expected RequestTrailers response type")
	})

	t.Run("response trailers response has correct type", func(t *testing.T) {
		resp := continueResponseTrailersResponse()
		require.NotNil(t, resp)

		_, ok := resp.Response.(*ext_proc_v3.ProcessingResponse_ResponseTrailers)
		assert.True(t, ok, "expected ResponseTrailers response type")
	})
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	t.Run("creates server without callback", func(t *testing.T) {
		s := NewServer(nil, nil)
		require.NotNil(t, s)
		assert.Nil(t, s.callback)
		assert.Nil(t, s.handler)
	})

	t.Run("creates server with callback", func(t *testing.T) {
		called := false
		cb := func(_ context.Context, _ *RouteContext, _ *ext_proc_v3.HttpHeaders) {
			called = true
		}

		s := NewServer(nil, cb)
		require.NotNil(t, s)
		require.NotNil(t, s.callback)

		// Verify callback is stored
		s.callback(nil, nil, nil)
		assert.True(t, called)
	})
}
