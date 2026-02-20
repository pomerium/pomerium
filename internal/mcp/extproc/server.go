package extproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
)

// Metadata namespace and field name constants shared between the authorize package
// (producer) and the extproc package (consumer). These must stay in sync; any
// mismatch silently breaks the ext_authz → ext_proc metadata pipeline.
const (
	// RouteContextMetadataNamespace is the namespace key used within ext_authz
	// DynamicMetadata where route context is stored.
	RouteContextMetadataNamespace = "com.pomerium.route-context"

	// ExtAuthzMetadataNamespace is the namespace where Envoy stores ext_authz's DynamicMetadata.
	ExtAuthzMetadataNamespace = "envoy.filters.http.ext_authz"

	// Field names within the route context metadata struct.
	FieldRouteID      = "route_id"
	FieldSessionID    = "session_id"
	FieldIsMCP        = "is_mcp"
	FieldUpstreamHost = "upstream_host"
)

// Callback is invoked when the ext_proc server receives a response headers message.
// It receives the extracted route context and response headers.
// This is primarily used for testing to verify that ext_proc is being invoked.
type Callback func(ctx context.Context, routeCtx *RouteContext, headers *ext_proc_v3.HttpHeaders)

// RouteContext holds context extracted from metadata set by ext_authz.
type RouteContext struct {
	RouteID      string
	SessionID    string
	IsMCP        bool
	UpstreamHost string // Actual upstream hostname from the route's To config
}

// Server implements the Envoy external processor service for MCP response interception.
// It handles upstream token injection on the request path and 401/403 interception
// on the response path (for auto-discovery OAuth flows).
type Server struct {
	ext_proc_v3.UnimplementedExternalProcessorServer

	handler  UpstreamRequestHandler
	callback Callback
}

// NewServer creates a new ext_proc server.
// The handler provides upstream token injection and 401/403 handling logic.
// The callback is optional and can be used for testing to verify ext_proc invocation.
func NewServer(handler UpstreamRequestHandler, callback Callback) *Server {
	return &Server{
		handler:  handler,
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

	// Track route context and request details across the stream.
	// Request details are captured during the RequestHeaders phase and passed to handleResponseHeaders.
	var (
		routeCtx       *RouteContext
		downstreamHost string // downstream :authority (used for HostInfo lookups, callback URLs)
		originalURL    string // full request URL built with the actual upstream host
	)

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
			// Capture request details for response handling.
			// downstreamHost is the :authority seen by the client (used for HostInfo lookups
			// and Pomerium callback URLs). upstreamHost is the actual backend server hostname
			// from route config (used for building originalURL and discovery).
			// Envoy rewrites :authority to the upstream host AFTER ext_proc processes
			// request headers, so ext_proc must get the upstream host from metadata.
			downstreamHost = getHeaderValue(v.RequestHeaders.GetHeaders(), ":authority")
			upstreamHost := downstreamHost
			if routeCtx != nil && routeCtx.UpstreamHost != "" {
				upstreamHost = routeCtx.UpstreamHost
			}
			scheme := getHeaderValue(v.RequestHeaders.GetHeaders(), ":scheme")
			if scheme != "http" && scheme != "https" {
				scheme = "https"
			}
			reqPath := getHeaderValue(v.RequestHeaders.GetHeaders(), ":path")
			u := &url.URL{Scheme: scheme, Host: upstreamHost}
			if parsed, err := url.Parse(reqPath); err == nil {
				u.Path = parsed.Path
				u.RawQuery = parsed.RawQuery
			} else {
				log.Ctx(ctx).Warn().Err(err).
					Str("path", reqPath).
					Msg("ext_proc: failed to parse request path, originalURL will have no path")
			}
			originalURL = u.String()

			log.Ctx(ctx).Debug().
				Bool("route_ctx_nil", routeCtx == nil).
				Msg("ext_proc: extracted route context from request headers")
			resp = s.handleRequestHeaders(ctx, v.RequestHeaders, routeCtx)

		case *ext_proc_v3.ProcessingRequest_ResponseHeaders:
			log.Ctx(ctx).Debug().
				Bool("route_ctx_nil", routeCtx == nil).
				Bool("has_callback", s.callback != nil).
				Msg("ext_proc: processing response headers")
			resp = s.handleResponseHeaders(ctx, v.ResponseHeaders, routeCtx, downstreamHost, originalURL)

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
			if grpcstatus.Code(err) == codes.Canceled {
				log.Ctx(ctx).Debug().Err(err).Msg("ext_proc: stream send canceled")
			} else {
				log.Ctx(ctx).Error().Err(err).Msg("ext_proc: stream send error")
			}
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
		log.Debug().Msg("ext_proc: route-context struct has no fields")
		return nil
	}

	return &RouteContext{
		RouteID:      fields[FieldRouteID].GetStringValue(),
		SessionID:    fields[FieldSessionID].GetStringValue(),
		IsMCP:        fields[FieldIsMCP].GetBoolValue(),
		UpstreamHost: fields[FieldUpstreamHost].GetStringValue(),
	}
}

// handleRequestHeaders processes incoming request headers.
// For MCP routes, injects cached upstream tokens via the handler.
func (s *Server) handleRequestHeaders(
	ctx context.Context,
	headers *ext_proc_v3.HttpHeaders,
	routeCtx *RouteContext,
) *ext_proc_v3.ProcessingResponse {
	if routeCtx == nil || !routeCtx.IsMCP {
		return continueRequestHeadersResponse()
	}

	downstreamHost := getHeaderValue(headers.GetHeaders(), ":authority")
	path := getHeaderValue(headers.GetHeaders(), ":path")
	method := getHeaderValue(headers.GetHeaders(), ":method")

	log.Ctx(ctx).Debug().
		Str("route_id", routeCtx.RouteID).
		Str("session_id", routeCtx.SessionID).
		Str("downstream_host", downstreamHost).
		Str("path", path).
		Str("method", method).
		Msg("ext_proc: processing MCP request")

	if s.handler == nil {
		return continueRequestHeadersResponse()
	}

	token, err := s.handler.GetUpstreamToken(ctx, routeCtx, downstreamHost)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).
			Str("route_id", routeCtx.RouteID).
			Str("downstream_host", downstreamHost).
			Msg("ext_proc: error getting upstream token, continuing without")
		return continueRequestHeadersResponse()
	}

	if token != "" {
		log.Ctx(ctx).Debug().
			Str("route_id", routeCtx.RouteID).
			Msg("ext_proc: injecting upstream token")
		return injectAuthorizationHeader(token)
	}

	return continueRequestHeadersResponse()
}

// handleResponseHeaders processes upstream response headers.
// For MCP routes, intercepts 401/403 responses to trigger upstream OAuth flows.
// downstreamHost is the client-facing :authority (for HostInfo lookups and callback URLs).
// originalURL is the full request URL built with the actual upstream host.
func (s *Server) handleResponseHeaders(
	ctx context.Context,
	headers *ext_proc_v3.HttpHeaders,
	routeCtx *RouteContext,
	downstreamHost string,
	originalURL string,
) *ext_proc_v3.ProcessingResponse {
	statusStr := getHeaderValue(headers.GetHeaders(), ":status")

	if routeCtx != nil && routeCtx.IsMCP {
		log.Ctx(ctx).Debug().
			Str("route_id", routeCtx.RouteID).
			Str("session_id", routeCtx.SessionID).
			Str("status", statusStr).
			Msg("ext_proc: processing MCP response")
	}

	// Invoke callback if set (for testing)
	if s.callback != nil {
		s.callback(ctx, routeCtx, headers)
	}

	if routeCtx == nil || !routeCtx.IsMCP || s.handler == nil {
		return continueResponseHeadersResponse()
	}

	// Parse status code
	var statusCode int
	if _, err := fmt.Sscanf(statusStr, "%d", &statusCode); err != nil {
		log.Ctx(ctx).Warn().
			Str("route_id", routeCtx.RouteID).
			Str("status_raw", statusStr).
			Msg("ext_proc: could not parse response status, passing through")
		return continueResponseHeadersResponse()
	}

	// Only handle 401 and 403 responses
	if statusCode != 401 && statusCode != 403 {
		return continueResponseHeadersResponse()
	}

	wwwAuthenticate := getHeaderValue(headers.GetHeaders(), "www-authenticate")

	log.Ctx(ctx).Info().
		Str("route_id", routeCtx.RouteID).
		Str("session_id", routeCtx.SessionID).
		Int("status", statusCode).
		Str("downstream_host", downstreamHost).
		Str("original_url", originalURL).
		Str("www_authenticate", wwwAuthenticate).
		Msg("ext_proc: upstream returned auth challenge, delegating to handler")

	action, err := s.handler.HandleUpstreamResponse(ctx, routeCtx, downstreamHost, originalURL, statusCode, wwwAuthenticate)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).
			Str("route_id", routeCtx.RouteID).
			Int("status", statusCode).
			Str("downstream_host", downstreamHost).
			Str("www_authenticate", wwwAuthenticate).
			Msg("ext_proc: error handling upstream response, passing through")
		return continueResponseHeadersResponse()
	}

	if action != nil && action.WWWAuthenticate != "" {
		log.Ctx(ctx).Info().
			Str("route_id", routeCtx.RouteID).
			Int("status", statusCode).
			Str("www_authenticate", action.WWWAuthenticate).
			Msg("ext_proc: returning 401 to trigger client re-authorization")
		return immediateUnauthorizedResponse(action.WWWAuthenticate)
	}

	log.Ctx(ctx).Debug().
		Str("route_id", routeCtx.RouteID).
		Int("status", statusCode).
		Msg("ext_proc: handler returned no action, passing through upstream response")

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
