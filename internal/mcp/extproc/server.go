package extproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
)

// RouteContextMetadataNamespace is the namespace key within ext_authz dynamic metadata
// where route context is stored.
const RouteContextMetadataNamespace = "com.pomerium.route-context"

// ExtAuthzMetadataNamespace is the namespace where Envoy stores ext_authz's DynamicMetadata.
// All dynamic metadata returned by ext_authz is stored under this namespace in stream info.
const ExtAuthzMetadataNamespace = "envoy.filters.http.ext_authz"

// Callback is invoked when the ext_proc server receives a response headers message.
// It receives the extracted route context and response headers.
// This is primarily used for testing to verify that ext_proc is being invoked.
type Callback func(ctx context.Context, routeCtx *RouteContext, headers *ext_proc_v3.HttpHeaders)

// RouteContext holds context extracted from metadata set by ext_authz.
type RouteContext struct {
	RouteID   string
	SessionID string
	IsMCP     bool
}

// Server implements the Envoy external processor service for MCP response interception.
// Currently, this is a no-op server that logs route and request details.
// Future implementation will handle 401/403 responses for upstream OAuth flows.
type Server struct {
	ext_proc_v3.UnimplementedExternalProcessorServer

	callback Callback
}

// NewServer creates a new ext_proc server.
// The callback is optional and can be used for testing to verify ext_proc invocation.
func NewServer(callback Callback) *Server {
	return &Server{
		callback: callback,
	}
}

// Register registers the ext_proc server with a gRPC server.
func (s *Server) Register(srv *grpc.Server) {
	ext_proc_v3.RegisterExternalProcessorServer(srv, s)
}

// Process handles the bidirectional streaming for request/response processing.
// This is called by Envoy for each request that has ext_proc enabled.
func (s *Server) Process(stream ext_proc_v3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()

	log.Ctx(ctx).Debug().Msg("ext_proc: Process stream started")

	// Track route context across the stream
	var routeCtx *RouteContext

	for {
		// Check for context cancellation before blocking on Recv
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if grpcstatus.Code(err) == codes.Canceled {
				log.Ctx(ctx).Debug().Err(err).Msg("ext_proc: stream canceled")
			} else {
				log.Ctx(ctx).Error().Err(err).Msg("ext_proc: stream recv error")
			}
			return err
		}

		var resp *ext_proc_v3.ProcessingResponse

		log.Ctx(ctx).Debug().
			Str("request_type", fmt.Sprintf("%T", req.Request)).
			Bool("has_metadata", req.GetMetadataContext() != nil).
			Msg("ext_proc: received message")

		switch v := req.Request.(type) {
		case *ext_proc_v3.ProcessingRequest_RequestHeaders:
			// Extract route context from metadata for later use
			routeCtx = s.extractRouteContext(req.GetMetadataContext())
			log.Ctx(ctx).Debug().
				Bool("route_ctx_nil", routeCtx == nil).
				Msg("ext_proc: extracted route context from request headers")
			resp = s.handleRequestHeaders(ctx, v.RequestHeaders, routeCtx)

		case *ext_proc_v3.ProcessingRequest_ResponseHeaders:
			// This is where we intercept responses (e.g., 401/403 for upstream OAuth)
			log.Ctx(ctx).Debug().
				Bool("route_ctx_nil", routeCtx == nil).
				Bool("has_callback", s.callback != nil).
				Msg("ext_proc: processing response headers")
			resp = s.handleResponseHeaders(ctx, v.ResponseHeaders, routeCtx)

		case *ext_proc_v3.ProcessingRequest_RequestBody:
			resp = continueRequestBodyResponse()

		case *ext_proc_v3.ProcessingRequest_ResponseBody:
			resp = continueResponseBodyResponse()

		case *ext_proc_v3.ProcessingRequest_RequestTrailers:
			resp = continueRequestTrailersResponse()

		case *ext_proc_v3.ProcessingRequest_ResponseTrailers:
			resp = continueResponseTrailersResponse()

		default:
			log.Ctx(ctx).Warn().
				Str("request_type", fmt.Sprintf("%T", req.Request)).
				Msg("ext_proc: received unknown request type")
			return grpcstatus.Errorf(codes.Unimplemented, "ext_proc: unrecognized request type %T", req.Request)
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// extractRouteContext extracts route context from the dynamic metadata set by ext_authz.
// The metadata path is: envoy.filters.http.ext_authz -> com.pomerium.route-context -> {fields}
func (s *Server) extractRouteContext(metadata *envoy_config_core_v3.Metadata) *RouteContext {
	if metadata == nil {
		return nil
	}

	filterMetadata := metadata.GetFilterMetadata()

	// Debug: log all available filter metadata keys (only evaluated if debug enabled)
	log.Debug().Func(func(e *zerolog.Event) {
		e.Strs("filter_metadata_keys", slices.Collect(maps.Keys(filterMetadata)))
	}).Msg("ext_proc: metadata structure")

	// ext_authz stores its DynamicMetadata under "envoy.filters.http.ext_authz" namespace
	extAuthzMetadata := filterMetadata[ExtAuthzMetadataNamespace]
	if extAuthzMetadata == nil {
		log.Debug().Msg("ext_proc: no ext_authz metadata found")
		return nil
	}

	// Within ext_authz metadata, find the route context
	extAuthzFields := extAuthzMetadata.GetFields()
	if extAuthzFields == nil {
		log.Debug().Msg("ext_proc: ext_authz metadata has no fields")
		return nil
	}

	routeContextValue := extAuthzFields[RouteContextMetadataNamespace]
	if routeContextValue == nil {
		log.Debug().Msg("ext_proc: no route-context in ext_authz metadata")
		return nil
	}

	routeContext := routeContextValue.GetStructValue()
	if routeContext == nil {
		log.Debug().Msg("ext_proc: route-context is not a struct")
		return nil
	}

	fields := routeContext.GetFields()
	if fields == nil {
		return nil
	}

	return &RouteContext{
		RouteID:   fields["route_id"].GetStringValue(),
		SessionID: fields["session_id"].GetStringValue(),
		IsMCP:     fields["is_mcp"].GetBoolValue(),
	}
}

// handleRequestHeaders processes incoming request headers.
// Currently a no-op that passes through.
func (s *Server) handleRequestHeaders(
	ctx context.Context,
	headers *ext_proc_v3.HttpHeaders,
	routeCtx *RouteContext,
) *ext_proc_v3.ProcessingResponse {
	// Log request details for debugging
	if routeCtx != nil && routeCtx.IsMCP {
		host := getHeaderValue(headers.GetHeaders(), ":authority")
		path := getHeaderValue(headers.GetHeaders(), ":path")
		method := getHeaderValue(headers.GetHeaders(), ":method")

		log.Ctx(ctx).Debug().
			Str("route_id", routeCtx.RouteID).
			Str("session_id", routeCtx.SessionID).
			Str("host", host).
			Str("path", path).
			Str("method", method).
			Msg("ext_proc: processing MCP request")
	}

	return continueRequestHeadersResponse()
}

// handleResponseHeaders processes upstream response headers.
// This is where 401/403 interception will be implemented for upstream OAuth flows.
// Currently a no-op that passes through.
func (s *Server) handleResponseHeaders(
	ctx context.Context,
	headers *ext_proc_v3.HttpHeaders,
	routeCtx *RouteContext,
) *ext_proc_v3.ProcessingResponse {
	// Log response details for debugging
	if routeCtx != nil && routeCtx.IsMCP {
		status := getHeaderValue(headers.GetHeaders(), ":status")

		log.Ctx(ctx).Debug().
			Str("route_id", routeCtx.RouteID).
			Str("session_id", routeCtx.SessionID).
			Str("status", status).
			Msg("ext_proc: processing MCP response")
	}

	// Invoke callback if set (for testing)
	if s.callback != nil {
		s.callback(ctx, routeCtx, headers)
	}

	// For now, always pass through the response unmodified.
	return continueResponseHeadersResponse()
}

// Phase-specific continue responses - each processing phase requires its own response type.

func continueRequestHeadersResponse() *ext_proc_v3.ProcessingResponse {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &ext_proc_v3.HeadersResponse{
				Response: &ext_proc_v3.CommonResponse{
					Status: ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

func continueResponseHeadersResponse() *ext_proc_v3.ProcessingResponse {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &ext_proc_v3.HeadersResponse{
				Response: &ext_proc_v3.CommonResponse{
					Status: ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

func continueRequestBodyResponse() *ext_proc_v3.ProcessingResponse {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_RequestBody{
			RequestBody: &ext_proc_v3.BodyResponse{
				Response: &ext_proc_v3.CommonResponse{
					Status: ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

func continueResponseBodyResponse() *ext_proc_v3.ProcessingResponse {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_ResponseBody{
			ResponseBody: &ext_proc_v3.BodyResponse{
				Response: &ext_proc_v3.CommonResponse{
					Status: ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

func continueRequestTrailersResponse() *ext_proc_v3.ProcessingResponse {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &ext_proc_v3.TrailersResponse{},
		},
	}
}

func continueResponseTrailersResponse() *ext_proc_v3.ProcessingResponse {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &ext_proc_v3.TrailersResponse{},
		},
	}
}

// getHeaderValue extracts a header value from the HeaderMap.
// It checks both the string Value and the byte RawValue fields,
// since Envoy sends pseudo-headers (:status, :authority, etc.) via RawValue.
func getHeaderValue(headers *envoy_config_core_v3.HeaderMap, key string) string {
	if headers == nil {
		return ""
	}
	for _, h := range headers.GetHeaders() {
		if h.GetKey() == key {
			if v := h.GetValue(); v != "" {
				return v
			}
			if raw := h.GetRawValue(); len(raw) > 0 {
				return string(raw)
			}
			return ""
		}
	}
	return ""
}
