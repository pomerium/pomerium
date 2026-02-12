package extproc

import (
	"context"
	"fmt"
	"io"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// mockProcessStream is a mock implementation of ExternalProcessor_ProcessServer for testing.
type mockProcessStream struct {
	ctx       context.Context
	requests  []*ext_proc_v3.ProcessingRequest
	responses []*ext_proc_v3.ProcessingResponse
	recvIdx   int
	sendErr   error
}

func (m *mockProcessStream) Send(resp *ext_proc_v3.ProcessingResponse) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.responses = append(m.responses, resp)
	return nil
}

func (m *mockProcessStream) Recv() (*ext_proc_v3.ProcessingRequest, error) {
	if m.recvIdx >= len(m.requests) {
		return nil, io.EOF
	}
	req := m.requests[m.recvIdx]
	m.recvIdx++
	return req, nil
}

func (m *mockProcessStream) Context() context.Context     { return m.ctx }
func (m *mockProcessStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockProcessStream) SendHeader(metadata.MD) error { return nil }
func (m *mockProcessStream) SetTrailer(metadata.MD)       {}
func (m *mockProcessStream) SendMsg(any) error            { return nil }
func (m *mockProcessStream) RecvMsg(any) error            { return nil }

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

	t.Run("falls back to RawValue when Value is empty", func(t *testing.T) {
		headers := &envoy_config_core_v3.HeaderMap{
			Headers: []*envoy_config_core_v3.HeaderValue{
				{Key: ":status", RawValue: []byte("200")},
			},
		}
		result := getHeaderValue(headers, ":status")
		assert.Equal(t, "200", result)
	})

	t.Run("prefers Value over RawValue when both set", func(t *testing.T) {
		headers := &envoy_config_core_v3.HeaderMap{
			Headers: []*envoy_config_core_v3.HeaderValue{
				{Key: ":status", Value: "200", RawValue: []byte("404")},
			},
		}
		result := getHeaderValue(headers, ":status")
		assert.Equal(t, "200", result)
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

	t.Run("creates server without handler or callback", func(t *testing.T) {
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

func TestProcess(t *testing.T) {
	t.Parallel()

	mcpMetadata := &envoy_config_core_v3.Metadata{
		FilterMetadata: map[string]*structpb.Struct{
			ExtAuthzMetadataNamespace: {
				Fields: map[string]*structpb.Value{
					RouteContextMetadataNamespace: {
						Kind: &structpb.Value_StructValue{
							StructValue: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									FieldRouteID:   structpb.NewStringValue("route-123"),
									FieldSessionID: structpb.NewStringValue("session-456"),
									FieldIsMCP:     structpb.NewBoolValue(true),
								},
							},
						},
					},
				},
			},
		},
	}

	t.Run("empty stream returns nil", func(t *testing.T) {
		s := NewServer(nil, nil)
		stream := &mockProcessStream{
			ctx:      t.Context(),
			requests: nil, // EOF immediately
		}
		err := s.Process(stream)
		assert.NoError(t, err)
	})

	t.Run("request and response headers happy path", func(t *testing.T) {
		var gotRouteCtx *RouteContext
		s := NewServer(nil, func(_ context.Context, rc *RouteContext, _ *ext_proc_v3.HttpHeaders) {
			gotRouteCtx = rc
		})

		stream := &mockProcessStream{
			ctx: t.Context(),
			requests: []*ext_proc_v3.ProcessingRequest{
				{
					MetadataContext: mcpMetadata,
					Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
						RequestHeaders: &ext_proc_v3.HttpHeaders{
							Headers: &envoy_config_core_v3.HeaderMap{
								Headers: []*envoy_config_core_v3.HeaderValue{
									{Key: ":authority", Value: "example.com"},
									{Key: ":path", Value: "/api"},
									{Key: ":method", Value: "POST"},
								},
							},
						},
					},
				},
				{
					Request: &ext_proc_v3.ProcessingRequest_ResponseHeaders{
						ResponseHeaders: &ext_proc_v3.HttpHeaders{
							Headers: &envoy_config_core_v3.HeaderMap{
								Headers: []*envoy_config_core_v3.HeaderValue{
									{Key: ":status", RawValue: []byte("200")},
								},
							},
						},
					},
				},
			},
		}

		err := s.Process(stream)
		assert.NoError(t, err)
		require.Len(t, stream.responses, 2)

		// First response should be RequestHeaders type
		_, ok := stream.responses[0].Response.(*ext_proc_v3.ProcessingResponse_RequestHeaders)
		assert.True(t, ok, "expected RequestHeaders response")

		// Second response should be ResponseHeaders type
		_, ok = stream.responses[1].Response.(*ext_proc_v3.ProcessingResponse_ResponseHeaders)
		assert.True(t, ok, "expected ResponseHeaders response")

		// Callback should have received route context
		require.NotNil(t, gotRouteCtx)
		assert.Equal(t, "route-123", gotRouteCtx.RouteID)
		assert.True(t, gotRouteCtx.IsMCP)
	})

	t.Run("body and trailer messages produce continue responses", func(t *testing.T) {
		s := NewServer(nil, nil)
		stream := &mockProcessStream{
			ctx: t.Context(),
			requests: []*ext_proc_v3.ProcessingRequest{
				{Request: &ext_proc_v3.ProcessingRequest_RequestBody{}},
				{Request: &ext_proc_v3.ProcessingRequest_ResponseBody{}},
				{Request: &ext_proc_v3.ProcessingRequest_RequestTrailers{}},
				{Request: &ext_proc_v3.ProcessingRequest_ResponseTrailers{}},
			},
		}

		err := s.Process(stream)
		assert.NoError(t, err)
		require.Len(t, stream.responses, 4)

		_, ok := stream.responses[0].Response.(*ext_proc_v3.ProcessingResponse_RequestBody)
		assert.True(t, ok, "expected RequestBody response")
		_, ok = stream.responses[1].Response.(*ext_proc_v3.ProcessingResponse_ResponseBody)
		assert.True(t, ok, "expected ResponseBody response")
		_, ok = stream.responses[2].Response.(*ext_proc_v3.ProcessingResponse_RequestTrailers)
		assert.True(t, ok, "expected RequestTrailers response")
		_, ok = stream.responses[3].Response.(*ext_proc_v3.ProcessingResponse_ResponseTrailers)
		assert.True(t, ok, "expected ResponseTrailers response")
	})

	t.Run("send error propagates", func(t *testing.T) {
		s := NewServer(nil, nil)
		stream := &mockProcessStream{
			ctx: t.Context(),
			requests: []*ext_proc_v3.ProcessingRequest{
				{Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: &ext_proc_v3.HttpHeaders{},
				}},
			},
			sendErr: fmt.Errorf("send failed"),
		}

		err := s.Process(stream)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "send failed")
	})

	t.Run("unknown request type returns Unimplemented", func(t *testing.T) {
		s := NewServer(nil, nil)
		stream := &mockProcessStream{
			ctx: t.Context(),
			requests: []*ext_proc_v3.ProcessingRequest{
				{Request: nil}, // nil request type
			},
		}

		err := s.Process(stream)
		assert.Error(t, err)
		st, ok := grpcstatus.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("canceled context returns context error", func(t *testing.T) {
		s := NewServer(nil, nil)
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // cancel immediately

		stream := &mockProcessStream{
			ctx: ctx,
			requests: []*ext_proc_v3.ProcessingRequest{
				{Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: &ext_proc_v3.HttpHeaders{},
				}},
			},
		}

		err := s.Process(stream)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("route context persists across stream messages", func(t *testing.T) {
		var callbackCount int
		var lastRouteCtx *RouteContext
		s := NewServer(nil, func(_ context.Context, rc *RouteContext, _ *ext_proc_v3.HttpHeaders) {
			callbackCount++
			lastRouteCtx = rc
		})

		stream := &mockProcessStream{
			ctx: t.Context(),
			requests: []*ext_proc_v3.ProcessingRequest{
				{
					MetadataContext: mcpMetadata,
					Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
						RequestHeaders: &ext_proc_v3.HttpHeaders{},
					},
				},
				// Body message in between (no metadata)
				{Request: &ext_proc_v3.ProcessingRequest_RequestBody{}},
				// Response headers -- should still have route context from request headers
				{
					Request: &ext_proc_v3.ProcessingRequest_ResponseHeaders{
						ResponseHeaders: &ext_proc_v3.HttpHeaders{
							Headers: &envoy_config_core_v3.HeaderMap{
								Headers: []*envoy_config_core_v3.HeaderValue{
									{Key: ":status", RawValue: []byte("200")},
								},
							},
						},
					},
				},
			},
		}

		err := s.Process(stream)
		assert.NoError(t, err)
		assert.Equal(t, 1, callbackCount)
		require.NotNil(t, lastRouteCtx)
		assert.Equal(t, "route-123", lastRouteCtx.RouteID)
	})
}
