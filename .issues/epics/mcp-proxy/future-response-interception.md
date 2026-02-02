---
id: future-response-interception
title: "Future: ext_proc for Response Interception and Reactive Discovery"
status: future
created: 2026-02-02
updated: 2026-02-02
priority: low
labels:
  - mcp
  - proxy
  - envoy
  - ext_proc
  - future
  - architecture
deps: []
---

# Future: ext_proc for Response Interception and Reactive Discovery

## Summary

This task documents the future capability needed for full MCP proxy support: using Envoy's **ext_proc** (External Processing) filter to intercept HTTP responses from upstream servers. This will enable reactive discovery (401 handling) and step-up authorization (403 insufficient_scope) as specified in the MCP authorization spec.

**Decision**: We will use **ext_proc** for response interception when this capability is implemented.

**Status**: OUT OF SCOPE for current epic. Documented for future reference.

## Current Limitation

### ext_authz Architecture

Pomerium uses Envoy's [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto) filter which:

- ✅ Intercepts **requests** before forwarding to upstream
- ✅ Can allow/deny requests
- ✅ Can modify request headers
- ✅ Can return custom responses (redirects, errors)
- ❌ **Cannot intercept responses** from upstream
- ❌ **Cannot modify responses** before returning to client

### Impact on MCP Proxy

Without response interception:

| MCP Spec Feature | Spec Mechanism | Current Workaround |
|-----------------|----------------|-------------------|
| Initial auth discovery | 401 + WWW-Authenticate | Proactive well-known probing on `initialize` |
| Step-up authorization | 403 + insufficient_scope | ❌ Not supported (upstream 403 goes directly to client) |
| Token refresh on 401 | Intercept 401, refresh, retry | ❌ Not supported (must pre-emptively refresh) |
| Scope hints from upstream | Parse WWW-Authenticate scope | ❌ Must use scopes_supported from metadata |

## Required Capabilities

### 1. Response Interception Filter

A new Envoy filter (or ext_proc usage) that can:

```
Upstream Response → [Response Filter] → Pomerium Logic → Client
                          │
                          ├─ Inspect status code (401, 403)
                          ├─ Parse response headers (WWW-Authenticate)
                          ├─ Optionally suppress response
                          ├─ Trigger authorization flow
                          └─ Retry original request with new token
```

### 2. Request-Response Correlation

To retry the original request after obtaining a token:

```go
type PendingRequest struct {
    // Original request details
    Method      string
    Path        string
    Headers     http.Header
    Body        []byte  // Must buffer for retry

    // Context
    UserID      string
    RouteID     string
    SessionID   string

    // For correlation
    RequestID   string
}
```

### 3. Response Handling Logic

```go
// ResponseInterceptor handles upstream responses
type ResponseInterceptor interface {
    // HandleResponse is called for each upstream response
    // Returns: (modifiedResponse, shouldRetry, error)
    HandleResponse(ctx context.Context, req *PendingRequest, resp *http.Response) (*http.Response, bool, error)
}

// MCP-specific implementation
func (h *MCPResponseHandler) HandleResponse(ctx context.Context, req *PendingRequest, resp *http.Response) (*http.Response, bool, error) {
    switch resp.StatusCode {
    case 401:
        // Parse WWW-Authenticate for resource_metadata
        wwwAuth := parseWWWAuthenticate(resp.Header.Get("WWW-Authenticate"))

        // Trigger OAuth flow (may require user redirect)
        token, err := h.choreographer.AcquireToken(ctx, req.UserID, req.RouteID, wwwAuth)
        if err != nil {
            return nil, false, err // Return original 401 to client
        }

        // Retry with token
        return nil, true, nil

    case 403:
        // Check for insufficient_scope
        wwwAuth := parseWWWAuthenticate(resp.Header.Get("WWW-Authenticate"))
        if wwwAuth.Error == "insufficient_scope" {
            // Trigger step-up authorization
            token, err := h.choreographer.StepUpAuthorization(ctx, req.UserID, req.RouteID, wwwAuth.Scope)
            if err != nil {
                return nil, false, err // Return original 403 to client
            }

            // Retry with new token
            return nil, true, nil
        }

        // Not insufficient_scope, pass through
        return resp, false, nil

    default:
        // Pass through all other responses
        return resp, false, nil
    }
}
```

## Envoy Integration: ext_proc

**Decision**: We will use Envoy's [ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) (External Processing) filter for response interception.

### Why ext_proc

ext_proc provides bidirectional streaming for both request and response processing, which is exactly what we need for:

1. **Response inspection**: Intercept 401/403 responses before they reach the client
2. **Header parsing**: Extract WWW-Authenticate details for reactive discovery
3. **Request retry**: Buffer original request and retry with acquired token
4. **Seamless integration**: Works alongside existing ext_authz for request-side authorization

### Envoy Configuration (YAML)

```yaml
http_filters:
  # Existing request authorization
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      # ... existing ext_authz config ...

  # NEW: Response interception for MCP proxy
  - name: envoy.filters.http.ext_proc
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
      grpc_service:
        envoy_grpc:
          cluster_name: pomerium_ext_proc
      processing_mode:
        request_header_mode: SKIP      # ext_authz handles requests
        response_header_mode: SEND     # We need to see response headers
        request_body_mode: NONE        # Don't send request body (future: BUFFERED for retry)
        response_body_mode: NONE       # Don't need response body
      failure_mode_allow: false        # Fail closed on ext_proc errors
      metadata_options:
        forwarding_namespaces:
          untyped:
            - "envoy.filters.http.ext_authz"  # Forward ext_authz context
```

### ext_proc Capabilities

| Capability | ext_proc Support | MCP Proxy Use Case |
|------------|-----------------|-------------------|
| Inspect response status | ✅ | Detect 401/403 |
| Parse response headers | ✅ | Extract WWW-Authenticate |
| Modify response headers | ✅ | Add debugging headers |
| Suppress response | ✅ | Hide 401 during token acquisition |
| Buffer request body | ✅ | Retry original request |
| Trigger new request | ✅ via ImmediateResponse | Retry with token |

### Considerations

- **Complexity**: ext_proc requires gRPC streaming implementation (more complex than ext_authz)
- **Memory**: Request body buffering has memory implications for large payloads
- **Latency**: Additional round-trip to Pomerium for response processing
- **Failure mode**: Must handle ext_proc unavailability gracefully

### Alternatives Considered (Not Chosen)

| Alternative | Why Not Chosen |
|-------------|---------------|
| Custom C++ Envoy filter | High maintenance burden, requires C++ expertise |
| Lua filter | Cannot trigger retries, limited capabilities |
| Client-side handling | Breaks zero-config goal, requires client changes |

---

## Implementation Details: go-control-plane Integration

### Package Import

```go
import (
    ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
    ext_proc_service "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
    envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
    envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
    "google.golang.org/protobuf/types/known/anypb"
    "google.golang.org/protobuf/types/known/durationpb"
)
```

### ExternalProcessor Configuration Struct

The `ExternalProcessor` is the root configuration for the ext_proc filter. Key fields:

| Field | Type | Purpose |
|-------|------|---------|
| `GrpcService` | `*v3.GrpcService` | Specifies gRPC cluster for external processor |
| `ProcessingMode` | `*ProcessingMode` | Granular control of what gets sent to processor |
| `FailureModeAllow` | `bool` | Fail-open behavior if processor unavailable |
| `MessageTimeout` | `*durationpb.Duration` | Timeout for individual processor messages |
| `MaxMessageTimeout` | `*durationpb.Duration` | Maximum override timeout |
| `AllowModeOverride` | `bool` | Allow processor to modify processing mode |
| `ObservabilityMode` | `bool` | "Send and Go" mode - doesn't wait for response |
| `ForwardRules` | `*HeaderForwardingRules` | Allow/deny lists for headers sent to processor |
| `MutationRules` | `*v31.HeaderMutationRules` | Header mutation policies |
| `MetadataOptions` | `*MetadataOptions` | Dynamic metadata forwarding/receiving |

### ProcessingMode Configuration

Controls which phases of HTTP processing are sent to the external processor:

**Header Send Mode Enum:**
```go
const (
    ProcessingMode_DEFAULT ProcessingMode_HeaderSendMode = 0  // Default behavior
    ProcessingMode_SEND    ProcessingMode_HeaderSendMode = 1  // Send to processor
    ProcessingMode_SKIP    ProcessingMode_HeaderSendMode = 2  // Don't send
)
```

**Body Send Mode Enum:**
```go
const (
    ProcessingMode_NONE                  ProcessingMode_BodySendMode = 0  // Don't send body
    ProcessingMode_STREAMED              ProcessingMode_BodySendMode = 1  // Stream in chunks
    ProcessingMode_BUFFERED              ProcessingMode_BodySendMode = 2  // Buffer entire body
    ProcessingMode_BUFFERED_PARTIAL      ProcessingMode_BodySendMode = 3  // Buffer with size limit
    ProcessingMode_FULL_DUPLEX_STREAMED  ProcessingMode_BodySendMode = 4  // Full duplex streaming
)
```

### Programmatic Filter Configuration

```go
// config/envoyconfig/ext_proc.go

func buildMCPExtProcFilter(clusterName string) (*envoy_http_connection_manager_v3.HttpFilter, error) {
    extProc := &ext_proc_v3.ExternalProcessor{
        // Configure gRPC service pointing to Pomerium's ext_proc handler
        GrpcService: &envoy_core_v3.GrpcService{
            TargetSpecifier: &envoy_core_v3.GrpcService_EnvoyGrpc_{
                EnvoyGrpc: &envoy_core_v3.GrpcService_EnvoyGrpc{
                    ClusterName: clusterName, // e.g., "pomerium-ext-proc"
                },
            },
        },

        // Configure processing modes for MCP response interception
        ProcessingMode: &ext_proc_v3.ProcessingMode{
            // ext_authz handles request authorization, so skip request headers
            RequestHeaderMode:  ext_proc_v3.ProcessingMode_SKIP,
            // Don't send request body (future: BUFFERED for retry after 401)
            RequestBodyMode:    ext_proc_v3.ProcessingMode_NONE,
            RequestTrailerMode: ext_proc_v3.ProcessingMode_SKIP,
            // We MUST see response headers to detect 401/403
            ResponseHeaderMode: ext_proc_v3.ProcessingMode_SEND,
            // Don't need response body for auth handling
            ResponseBodyMode:   ext_proc_v3.ProcessingMode_NONE,
            ResponseTrailerMode: ext_proc_v3.ProcessingMode_SKIP,
        },

        // Fail closed - if ext_proc is unavailable, fail the request
        // (We don't want to send requests without MCP token handling)
        FailureModeAllow: false,

        // Message timeout for processor response
        MessageTimeout: &durationpb.Duration{Seconds: 10},

        // Forward route context metadata to ext_proc
        MetadataOptions: &ext_proc_v3.MetadataOptions{
            ForwardingNamespaces: &ext_proc_v3.MetadataOptions_MetadataNamespaces{
                // Forward the route context set by ext_authz or Lua
                Untyped: []string{
                    "com.pomerium.route-context",
                    "envoy.filters.http.ext_authz",
                },
            },
            ReceivingNamespaces: &ext_proc_v3.MetadataOptions_MetadataNamespaces{
                // Allow ext_proc to set metadata for downstream filters
                Untyped: []string{"com.pomerium.mcp-auth"},
            },
        },

        // Only forward headers we need
        ForwardRules: &ext_proc_v3.HeaderForwardingRules{
            AllowedHeaders: &envoy_type_matcher_v3.ListStringMatcher{
                Patterns: []*envoy_type_matcher_v3.StringMatcher{
                    {MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{Exact: "www-authenticate"}},
                    {MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{Exact: "content-type"}},
                    {MatchPattern: &envoy_type_matcher_v3.StringMatcher_Prefix{Prefix: "x-pomerium-"}},
                },
            },
        },
    }

    // Marshal to Any for filter chain
    extProcAny, err := anypb.New(extProc)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal ext_proc config: %w", err)
    }

    return &envoy_http_connection_manager_v3.HttpFilter{
        Name: "envoy.filters.http.ext_proc",
        ConfigType: &envoy_http_connection_manager_v3.HttpFilter_TypedConfig{
            TypedConfig: extProcAny,
        },
    }, nil
}
```

### Per-Route ext_proc Configuration

For MCP routes that need response interception vs non-MCP routes that don't:

```go
// ExtProcPerRoute allows per-route overrides
func buildExtProcPerRouteConfig(enableForMCP bool) (*anypb.Any, error) {
    if !enableForMCP {
        // Disable ext_proc for non-MCP routes
        perRoute := &ext_proc_v3.ExtProcPerRoute{
            Override: &ext_proc_v3.ExtProcPerRoute_Disabled{
                Disabled: true,
            },
        }
        return anypb.New(perRoute)
    }

    // For MCP routes, use default config or override processing mode
    perRoute := &ext_proc_v3.ExtProcPerRoute{
        Override: &ext_proc_v3.ExtProcPerRoute_Overrides{
            Overrides: &ext_proc_v3.ExtProcOverrides{
                ProcessingMode: &ext_proc_v3.ProcessingMode{
                    RequestHeaderMode:  ext_proc_v3.ProcessingMode_SKIP,
                    RequestBodyMode:    ext_proc_v3.ProcessingMode_NONE,  // Future: BUFFERED for retry
                    ResponseHeaderMode: ext_proc_v3.ProcessingMode_SEND,
                    ResponseBodyMode:   ext_proc_v3.ProcessingMode_NONE,
                },
            },
        },
    }
    return anypb.New(perRoute)
}

// Apply to route configuration
func (b *Builder) buildMCPRoute(policy *config.Policy) (*envoy_config_route_v3.Route, error) {
    // ... existing route building ...

    route.TypedPerFilterConfig = map[string]*anypb.Any{
        // Existing ext_authz per-filter config
        "envoy.filters.http.ext_authz": extAuthzPerRoute,
        // NEW: Enable ext_proc for this MCP route
        "envoy.filters.http.ext_proc": extProcPerRoute,
    }

    return route, nil
}
```

---

## Route Context Propagation to ext_proc

### Current Pomerium Architecture

Pomerium already passes route information through ext_authz using **context extensions**:

**Location**: `config/envoyconfig/per_filter_config.go`

```go
// MakeExtAuthzContextExtensions creates context extensions with route info
func MakeExtAuthzContextExtensions(internal bool, routeID string, routeChecksum uint64) map[string]string {
    return map[string]string{
        "internal":       strconv.FormatBool(internal),
        "route_id":       routeID,
        "route_checksum": strconv.FormatUint(routeChecksum, 10),
    }
}
```

**Applied to routes** in `config/envoyconfig/routes.go`:

```go
extAuthzOpts := MakeExtAuthzContextExtensions(false, routeID, routeChecksum)
extAuthzCfg := PerFilterConfigExtAuthzContextExtensions(extAuthzOpts)
if policy.IsMCPServer() {
    extAuthzCfg = PerFilterConfigExtAuthzContextExtensionsWithBody(...)
}
route.TypedPerFilterConfig = map[string]*anypb.Any{
    PerFilterConfigExtAuthzName: extAuthzCfg,
}
```

### How ext_authz Receives Route Context

**Location**: `authorize/grpc.go`

```go
func (a *Authorize) getEvaluatorRequestFromCheckRequest(...) (*evaluator.Request, error) {
    attrs := in.GetAttributes()
    req := &evaluator.Request{
        IsInternal:         envoyconfig.ExtAuthzContextExtensionsIsInternal(attrs.GetContextExtensions()),
        EnvoyRouteChecksum: envoyconfig.ExtAuthzContextExtensionsRouteChecksum(attrs.GetContextExtensions()),
        EnvoyRouteID:       envoyconfig.ExtAuthzContextExtensionsRouteID(attrs.GetContextExtensions()),
    }
    req.Policy = a.getMatchingPolicy(req.EnvoyRouteID)  // Matches route to policy
    return req, nil
}
```

### Route Context Propagation: ext_authz Dynamic Metadata

**Decision**: ext_authz will set dynamic metadata containing route context that ext_proc can read.

**Why this approach:**

1. **Already in ext_authz response path** - No additional Lua filter needed
2. **Secure** - Metadata is internal to Envoy, not exposed in headers
3. **Efficient** - Metadata flows through Envoy's internal context
4. **Consistent** - Similar pattern to client certificate handling
5. **Rich context** - Can include user_id, session_id, policy details

**Data Flow:**

```
┌─────────┐     ┌──────────────┐     ┌─────────────────┐     ┌──────────┐
│ Client  │────▶│   ext_authz  │────▶│    ext_proc     │────▶│ Upstream │
│         │     │              │     │                 │     │          │
│         │     │ Sets dynamic │     │ Reads metadata: │     │          │
│         │     │ metadata:    │     │ - route_id      │     │          │
│         │     │ - route_id   │     │ - user_id       │     │          │
│         │     │ - user_id    │     │ - session_id    │     │          │
│         │     │ - session_id │     │ - is_mcp        │     │          │
│         │     │ - is_mcp     │     │                 │     │          │
└─────────┘     └──────────────┘     └─────────────────┘     └──────────┘
                                              │
                                              ▼
                                     On 401/403 response:
                                     1. Read route_id from metadata
                                     2. Look up policy by route_id
                                     3. Trigger token refresh/acquisition
                                     4. Retry request with new token
```

#### Implementation: ext_authz Sets Dynamic Metadata

In `authorize/grpc.go`, when returning CheckResponse:

```go
func (a *Authorize) buildCheckResponse(ctx context.Context, req *evaluator.Request, result *evaluator.Result) *ext_authz_v3.CheckResponse {
    // ... existing response building ...

    // Set dynamic metadata for ext_proc to read
    resp.DynamicMetadata = &structpb.Struct{
        Fields: map[string]*structpb.Value{
            "com.pomerium.route-context": {
                Kind: &structpb.Value_StructValue{
                    StructValue: &structpb.Struct{
                        Fields: map[string]*structpb.Value{
                            "route_id":    structpb.NewStringValue(req.EnvoyRouteID),
                            "user_id":     structpb.NewStringValue(req.Session.GetUserId()),
                            "session_id":  structpb.NewStringValue(req.Session.GetId()),
                            "is_mcp":      structpb.NewBoolValue(req.Policy.IsMCPServer()),
                        },
                    },
                },
            },
        },
    }

    return resp
}
```

#### Implementation: ext_proc Reads Metadata

ext_proc receives the metadata via `MetadataContext`:

```go
func (s *ExtProcServer) Process(stream ext_proc_service.ExternalProcessor_ProcessServer) error {
    for {
        req, err := stream.Recv()
        if err != nil {
            return err
        }

        // Extract route context from metadata
        routeCtx := req.GetMetadataContext().GetFilterMetadata()["com.pomerium.route-context"]
        if routeCtx != nil {
            routeID := routeCtx.GetFields()["route_id"].GetStringValue()
            userID := routeCtx.GetFields()["user_id"].GetStringValue()
            // ... use for response handling
        }

        // ... process request
    }
}
```

#### Alternatives Considered (Not Chosen)

| Alternative | Why Not Chosen |
|-------------|---------------|
| **Lua filter sets route metadata** | Requires additional Lua script; ext_authz already has the context |
| **Request headers with HMAC** | Exposes route info in headers; less secure than internal metadata |

---

## ext_proc Server Implementation

### gRPC Service Interface

The ext_proc server implements `ExternalProcessorServer`:

```go
// From github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3
type ExternalProcessorServer interface {
    // Process is a bidirectional streaming RPC
    Process(ExternalProcessor_ProcessServer) error
}

type ExternalProcessor_ProcessServer interface {
    Send(*ProcessingResponse) error
    Recv() (*ProcessingRequest, error)
    grpc.ServerStream
}
```

### ProcessingRequest Variants

The `ProcessingRequest` uses a oneof to send different processing stages:

```go
type ProcessingRequest struct {
    // One of:
    // - *ProcessingRequest_RequestHeaders
    // - *ProcessingRequest_RequestBody
    // - *ProcessingRequest_RequestTrailers
    // - *ProcessingRequest_ResponseHeaders  ← Key for 401/403 interception
    // - *ProcessingRequest_ResponseBody
    // - *ProcessingRequest_ResponseTrailers
    Request isProcessingRequest_Request

    // Metadata from ext_authz and other filters
    MetadataContext *v3.Metadata

    // Custom attributes
    Attributes map[string]*structpb.Struct
}
```

### ProcessingResponse Actions

**CommonResponse Status:**
```go
const (
    CommonResponse_CONTINUE             CommonResponse_ResponseStatus = 0  // Pass through unmodified
    CommonResponse_CONTINUE_AND_REPLACE CommonResponse_ResponseStatus = 1  // Apply mutations then continue
)
```

**ImmediateResponse** - Short-circuit processing:
```go
type ImmediateResponse struct {
    Status     *v3.HttpStatus     // HTTP status code
    Headers    *HeaderMutation    // Response headers
    Body       []byte             // Response body
    GrpcStatus *GrpcStatus        // For gRPC responses
    Details    string             // Error details
}
```

### Complete Server Implementation

```go
// internal/mcp/ext_proc_server.go

package mcp

import (
    "context"
    "io"

    ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
    envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
    envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
    "google.golang.org/grpc"
)

// ExtProcServer implements the Envoy external processor service for MCP response interception
type ExtProcServer struct {
    ext_proc_v3.UnimplementedExternalProcessorServer

    choreographer *AuthorizationChoreographer
    storage       *Storage
    hostInfo      *HostInfo
}

// NewExtProcServer creates a new ext_proc server
func NewExtProcServer(choreographer *AuthorizationChoreographer, storage *Storage, hostInfo *HostInfo) *ExtProcServer {
    return &ExtProcServer{
        choreographer: choreographer,
        storage:       storage,
        hostInfo:      hostInfo,
    }
}

// Register registers the ext_proc server with a gRPC server
func (s *ExtProcServer) Register(srv *grpc.Server) {
    ext_proc_v3.RegisterExternalProcessorServer(srv, s)
}

// Process handles the bidirectional streaming for request/response processing
func (s *ExtProcServer) Process(stream ext_proc_v3.ExternalProcessor_ProcessServer) error {
    ctx := stream.Context()

    // Track request context across the stream
    var reqCtx *requestContext

    for {
        req, err := stream.Recv()
        if err == io.EOF {
            return nil
        }
        if err != nil {
            return err
        }

        var resp *ext_proc_v3.ProcessingResponse

        switch v := req.Request.(type) {
        case *ext_proc_v3.ProcessingRequest_RequestHeaders:
            // Extract route context from metadata for later use
            reqCtx = s.extractRequestContext(req.GetMetadataContext())
            resp = s.handleRequestHeaders(ctx, v.RequestHeaders, reqCtx)

        case *ext_proc_v3.ProcessingRequest_RequestBody:
            // Not currently used (RequestBodyMode = NONE)
            // Future: Buffer request body for retry after 401
            resp = s.handleRequestBody(ctx, v.RequestBody, reqCtx)

        case *ext_proc_v3.ProcessingRequest_ResponseHeaders:
            // KEY: This is where we intercept 401/403 responses
            resp = s.handleResponseHeaders(ctx, v.ResponseHeaders, reqCtx)

        default:
            // Pass through other stages
            resp = &ext_proc_v3.ProcessingResponse{
                Response: &ext_proc_v3.ProcessingResponse_ResponseHeaders{
                    ResponseHeaders: &ext_proc_v3.HeadersResponse{
                        Response: &ext_proc_v3.CommonResponse{
                            Status: ext_proc_v3.CommonResponse_CONTINUE,
                        },
                    },
                },
            }
        }

        if err := stream.Send(resp); err != nil {
            return err
        }
    }
}

// requestContext holds context extracted from metadata
type requestContext struct {
    RouteID   string
    UserID    string
    SessionID string
    IsMCP     bool
}

// extractRequestContext extracts route context from ext_authz metadata
func (s *ExtProcServer) extractRequestContext(metadata *envoy_core_v3.Metadata) *requestContext {
    if metadata == nil {
        return nil
    }

    routeCtx := metadata.GetFilterMetadata()["com.pomerium.route-context"]
    if routeCtx == nil {
        return nil
    }

    return &requestContext{
        RouteID:   routeCtx.GetFields()["route_id"].GetStringValue(),
        UserID:    routeCtx.GetFields()["user_id"].GetStringValue(),
        SessionID: routeCtx.GetFields()["session_id"].GetStringValue(),
        IsMCP:     routeCtx.GetFields()["is_mcp"].GetBoolValue(),
    }
}

// handleRequestHeaders processes incoming request headers
func (s *ExtProcServer) handleRequestHeaders(ctx context.Context, headers *ext_proc_v3.HttpHeaders, reqCtx *requestContext) *ext_proc_v3.ProcessingResponse {
    // For MCP routes, we may want to capture the original request for retry
    // For now, just continue
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

// handleRequestBody handles request body (not currently used with RequestBodyMode = NONE)
// Future: When RequestBodyMode = BUFFERED, this will store the body for retry after 401
func (s *ExtProcServer) handleRequestBody(ctx context.Context, body *ext_proc_v3.HttpBody, reqCtx *requestContext) *ext_proc_v3.ProcessingResponse {
    // Not currently invoked (RequestBodyMode = NONE)
    // Future: Store buffered body for retry after 401
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

// handleResponseHeaders intercepts upstream responses - KEY METHOD for MCP auth
func (s *ExtProcServer) handleResponseHeaders(ctx context.Context, headers *ext_proc_v3.HttpHeaders, reqCtx *requestContext) *ext_proc_v3.ProcessingResponse {
    // Skip non-MCP routes
    if reqCtx == nil || !reqCtx.IsMCP {
        return s.continueResponse()
    }

    // Extract status code from headers
    statusCode := s.extractStatusCode(headers)

    switch statusCode {
    case 401:
        return s.handleUpstream401(ctx, headers, reqCtx)

    case 403:
        return s.handleUpstream403(ctx, headers, reqCtx)

    default:
        // Pass through all other responses
        return s.continueResponse()
    }
}

// extractStatusCode extracts HTTP status from response headers
func (s *ExtProcServer) extractStatusCode(headers *ext_proc_v3.HttpHeaders) int {
    for _, h := range headers.GetHeaders().GetHeaders() {
        if h.GetKey() == ":status" {
            // Parse status code
            var code int
            fmt.Sscanf(h.GetValue(), "%d", &code)
            return code
        }
    }
    return 0
}

// handleUpstream401 handles 401 Unauthorized from upstream
func (s *ExtProcServer) handleUpstream401(ctx context.Context, headers *ext_proc_v3.HttpHeaders, reqCtx *requestContext) *ext_proc_v3.ProcessingResponse {
    // Parse WWW-Authenticate header
    wwwAuth := s.extractWWWAuthenticate(headers)

    // Attempt token refresh or acquisition
    action, err := s.choreographer.HandleUpstream401(ctx, reqCtx.UserID, reqCtx.RouteID, wwwAuth)
    if err != nil {
        // Cannot handle, pass through the 401 to client
        return s.continueResponse()
    }

    switch action.Type {
    case ActionRetryWithToken:
        // TODO: Trigger retry with new token
        // This requires buffered request body and ImmediateResponse
        return s.buildRetryResponse(action.Token)

    case ActionRedirectForAuth:
        // Return redirect to user for interactive auth
        return s.buildRedirectResponse(action.RedirectURL)

    default:
        // Pass through original response
        return s.continueResponse()
    }
}

// handleUpstream403 handles 403 Forbidden with potential insufficient_scope
func (s *ExtProcServer) handleUpstream403(ctx context.Context, headers *ext_proc_v3.HttpHeaders, reqCtx *requestContext) *ext_proc_v3.ProcessingResponse {
    wwwAuth := s.extractWWWAuthenticate(headers)

    // Check if this is an insufficient_scope error
    if wwwAuth == nil || wwwAuth.Error != "insufficient_scope" {
        // Not a scope error, pass through
        return s.continueResponse()
    }

    // Attempt step-up authorization
    action, err := s.choreographer.HandleUpstream403InsufficientScope(ctx, reqCtx.UserID, reqCtx.RouteID, wwwAuth.Scope)
    if err != nil {
        return s.continueResponse()
    }

    switch action.Type {
    case ActionRetryWithToken:
        return s.buildRetryResponse(action.Token)

    case ActionRedirectForAuth:
        return s.buildRedirectResponse(action.RedirectURL)

    default:
        return s.continueResponse()
    }
}

// extractWWWAuthenticate parses the WWW-Authenticate header
func (s *ExtProcServer) extractWWWAuthenticate(headers *ext_proc_v3.HttpHeaders) *WWWAuthenticateHeader {
    for _, h := range headers.GetHeaders().GetHeaders() {
        if h.GetKey() == "www-authenticate" {
            return parseWWWAuthenticate(h.GetValue())
        }
    }
    return nil
}

// continueResponse returns a response that passes through unchanged
func (s *ExtProcServer) continueResponse() *ext_proc_v3.ProcessingResponse {
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

// buildRedirectResponse returns an immediate redirect response to client
func (s *ExtProcServer) buildRedirectResponse(redirectURL string) *ext_proc_v3.ProcessingResponse {
    return &ext_proc_v3.ProcessingResponse{
        Response: &ext_proc_v3.ProcessingResponse_ImmediateResponse{
            ImmediateResponse: &ext_proc_v3.ImmediateResponse{
                Status: &envoy_type_v3.HttpStatus{
                    Code: envoy_type_v3.StatusCode_Found, // 302
                },
                Headers: &ext_proc_v3.HeaderMutation{
                    SetHeaders: []*envoy_core_v3.HeaderValueOption{
                        {
                            Header: &envoy_core_v3.HeaderValue{
                                Key:   "Location",
                                Value: redirectURL,
                            },
                        },
                        {
                            Header: &envoy_core_v3.HeaderValue{
                                Key:   "Content-Type",
                                Value: "text/html",
                            },
                        },
                    },
                },
                Body: []byte(fmt.Sprintf(`<html><body>Redirecting to <a href="%s">authorization</a></body></html>`, redirectURL)),
            },
        },
    }
}

// buildRetryResponse triggers a retry with the new token
// NOTE: This is complex - may need to use ImmediateResponse with internal redirect
// or coordinate with ext_authz for token injection
func (s *ExtProcServer) buildRetryResponse(token string) *ext_proc_v3.ProcessingResponse {
    // TODO: Implement retry mechanism
    // Options:
    // 1. Internal redirect back through ext_authz with token hint
    // 2. Store token in metadata, have ext_authz inject it
    // 3. Use Envoy's retry mechanism with header modification

    // For now, this is a placeholder
    return s.continueResponse()
}
```

### WWW-Authenticate Parsing

```go
// internal/mcp/www_authenticate.go

package mcp

import (
    "regexp"
    "strings"
)

// WWWAuthenticateHeader represents a parsed WWW-Authenticate header
type WWWAuthenticateHeader struct {
    Scheme           string   // "Bearer"
    Realm            string   // Optional realm
    Error            string   // e.g., "insufficient_scope"
    ErrorDescription string   // Human-readable error
    Scope            []string // Required scopes
    ResourceMetadata string   // URL to resource metadata (MCP spec)
}

// parseWWWAuthenticate parses a WWW-Authenticate header value
// Example: Bearer realm="mcp", error="insufficient_scope", scope="read write", resource_metadata="https://example.com/.well-known/oauth-protected-resource"
func parseWWWAuthenticate(value string) *WWWAuthenticateHeader {
    if value == "" {
        return nil
    }

    header := &WWWAuthenticateHeader{}

    // Extract scheme
    parts := strings.SplitN(value, " ", 2)
    header.Scheme = parts[0]

    if len(parts) < 2 {
        return header
    }

    // Parse key-value pairs
    params := parts[1]
    paramRegex := regexp.MustCompile(`(\w+)="([^"]*)"`)
    matches := paramRegex.FindAllStringSubmatch(params, -1)

    for _, match := range matches {
        key := strings.ToLower(match[1])
        val := match[2]

        switch key {
        case "realm":
            header.Realm = val
        case "error":
            header.Error = val
        case "error_description":
            header.ErrorDescription = val
        case "scope":
            header.Scope = strings.Fields(val)
        case "resource_metadata":
            header.ResourceMetadata = val
        }
    }

    return header
}
```

## Integration with Existing MCP Code

### Current Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Pomerium MCP Code                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ ext_authz   │  │  Handlers   │  │  Storage    │         │
│  │ (request)   │  │             │  │             │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│         └────────────────┼────────────────┘                 │
│                          │                                  │
│                   ┌──────▼──────┐                           │
│                   │  host_info  │                           │
│                   │  storage    │                           │
│                   │  token      │                           │
│                   └─────────────┘                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Future Architecture with Response Interception

```
┌─────────────────────────────────────────────────────────────┐
│                     Pomerium MCP Code                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ ext_authz   │  │  ext_proc   │  │  Handlers   │         │
│  │ (request)   │  │ (response)  │  │             │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│         │         ┌──────▼──────┐         │                 │
│         │         │  Response   │         │                 │
│         │         │ Interceptor │         │                 │
│         │         └──────┬──────┘         │                 │
│         │                │                │                 │
│         └────────────────┼────────────────┘                 │
│                          │                                  │
│                   ┌──────▼──────┐                           │
│                   │Authorization│                           │
│                   │Choreographer│ ◄── Enhanced with         │
│                   └──────┬──────┘     reactive triggers     │
│                          │                                  │
│                   ┌──────▼──────┐                           │
│                   │  host_info  │                           │
│                   │  storage    │                           │
│                   │  token      │                           │
│                   └─────────────┘                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Code Changes Required

#### 1. New ext_proc Server

```go
// internal/mcp/ext_proc_server.go

// ExtProcServer implements envoy.service.ext_proc.v3.ExternalProcessorServer
type ExtProcServer struct {
    choreographer *AuthorizationChoreographer
    storage       *Storage
    hostInfo      *HostInfo
}

func (s *ExtProcServer) Process(stream extproc.ExternalProcessor_ProcessServer) error {
    for {
        req, err := stream.Recv()
        if err != nil {
            return err
        }

        switch v := req.Request.(type) {
        case *extproc.ProcessingRequest_ResponseHeaders:
            resp := s.handleResponseHeaders(stream.Context(), v.ResponseHeaders)
            if err := stream.Send(resp); err != nil {
                return err
            }
        }
    }
}
```

#### 2. Authorization Choreographer Enhancement

```go
// internal/mcp/authorization_choreographer.go

// Add reactive trigger methods
func (c *AuthorizationChoreographer) HandleUpstream401(
    ctx context.Context,
    userID, routeID string,
    wwwAuth *WWWAuthenticateHeader,
) (*AuthorizationAction, error) {
    // This is called by ext_proc when upstream returns 401

    // 1. Parse WWW-Authenticate for discovery hints
    // 2. Check if we have a cached token (may have expired)
    // 3. Try refresh if refresh token available
    // 4. If refresh fails, initiate new authorization
    // 5. Return action (retry with token, redirect user, or pass through error)
}

func (c *AuthorizationChoreographer) HandleUpstream403InsufficientScope(
    ctx context.Context,
    userID, routeID string,
    requiredScopes []string,
) (*AuthorizationAction, error) {
    // Step-up authorization flow
    // 1. Current token has insufficient scope
    // 2. Initiate new authorization with expanded scopes
    // 3. Return action (retry with new token, redirect user)
}
```

#### 3. Request Buffering for Retry

```go
// internal/mcp/request_buffer.go

// RequestBuffer stores pending requests for retry after auth
type RequestBuffer struct {
    storage *databroker.Client
}

func (b *RequestBuffer) Store(ctx context.Context, req *PendingRequest) (string, error) {
    // Store request in databroker with short TTL
    // Return request ID for correlation
}

func (b *RequestBuffer) Retrieve(ctx context.Context, requestID string) (*PendingRequest, error) {
    // Retrieve and delete buffered request
}
```

## Migration Path

### Phase 1: Current (Proactive Discovery)
- `initialize` interception triggers discovery
- Well-known endpoint probing
- Pre-emptive token refresh
- No step-up authorization support

### Phase 2: ext_proc Implementation
- Add ext_proc gRPC server alongside ext_authz
- Implement response header inspection
- Wire to existing choreographer

### Phase 3: Reactive Discovery
- Handle 401 responses reactively
- Parse WWW-Authenticate for better scope hints
- Implement request buffering for retry

### Phase 4: Step-Up Authorization
- Handle 403 insufficient_scope
- Implement incremental scope requests
- Full MCP authorization spec compliance

## Acceptance Criteria (Future)

1. ext_proc server handles upstream 401 responses
2. WWW-Authenticate header is parsed for discovery hints
3. Requests are buffered and retried after token acquisition
4. 403 insufficient_scope triggers step-up authorization
5. Scope from WWW-Authenticate is used (priority over scopes_supported)
6. Existing proactive discovery continues to work (fallback)
7. Performance impact is acceptable (< 10ms added latency)

## Filter Chain Order

The ext_proc filter must be positioned correctly in the filter chain:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HTTP Filter Chain                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────────┐                                               │
│   │ 1. Lua filter   │  Sets client cert metadata                    │
│   │ (existing)      │  namespace: com.pomerium.client-certificate   │
│   └────────┬────────┘                                               │
│            │                                                         │
│            ▼                                                         │
│   ┌─────────────────┐                                               │
│   │ 2. ext_authz    │  Request authorization                        │
│   │ (existing)      │  Sets: com.pomerium.route-context metadata    │
│   └────────┬────────┘                                               │
│            │                                                         │
│            ▼                                                         │
│   ┌─────────────────┐                                               │
│   │ 3. ext_proc     │  Response interception (NEW)                  │
│   │ (new for MCP)   │  Reads: com.pomerium.route-context            │
│   │                 │  Handles: 401/403 responses                   │
│   └────────┬────────┘                                               │
│            │                                                         │
│            ▼                                                         │
│   ┌─────────────────┐                                               │
│   │ 4. Router       │  Forwards to upstream                         │
│   └─────────────────┘                                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Key ordering considerations:**
1. **ext_authz before ext_proc**: ext_authz sets the route context metadata that ext_proc needs
2. **ext_proc before router**: ext_proc must be able to intercept responses before they reach the client
3. **Per-route disable**: Non-MCP routes should disable ext_proc via `ExtProcPerRoute.Disabled = true`

## Open Questions

### 1. Retry Mechanism

How to implement request retry after 401 token acquisition:

| Option | Pros | Cons |
|--------|------|------|
| **ImmediateResponse with internal redirect** | Clean, uses Envoy primitives | Complex URL construction, may lose body |
| **Store request in databroker, redirect through ext_authz** | Token injection happens naturally | Requires correlation ID, added latency |
| **ext_proc modifies response to include retry instructions** | Simple implementation | Requires client cooperation |
| **Envoy retry policy with ext_proc header modification** | Leverages Envoy retry | May not work for 401 (not a retry-able status) |

**Recommendation**: Start with ImmediateResponse redirect for interactive flows, implement databroker-based buffering for API requests.

### 2. Body Buffering (Deferred)

**Initial implementation**: `RequestBodyMode = NONE` - no body buffering, cannot retry requests.

**Future enhancement**: When retry support is needed, change to `RequestBodyMode = BUFFERED`. Considerations:

- **Max body size**: MCP requests should be small (JSON-RPC), but need a reasonable limit (e.g., 1MB)
- **Memory impact**: Large concurrent requests could cause memory pressure
- **TTL**: Buffered requests should expire quickly (e.g., 30 seconds)

### 3. Streaming Requests

JSON-RPC doesn't typically use streaming, but consider:
- Should streaming requests be supported for retry?
- If not, should ext_proc fail-open for streaming requests?

## References

- [Envoy ext_proc documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)
- [ext_proc gRPC API](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto)
- [go-control-plane ext_proc v3](https://pkg.go.dev/github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3) - Filter configuration types
- [go-control-plane ext_proc service](https://pkg.go.dev/github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3) - gRPC service interface
- [MCP Authorization Spec](/.docs/mcp/basic/authorization.mdx) - Scope Challenge Handling, Step-Up Authorization
- [upstream-discovery.md](./upstream-discovery.md) - Current proactive discovery workaround
- [authorization-choreographer.md](./authorization-choreographer.md) - Current choreographer design

### Pomerium Codebase References

- `config/envoyconfig/per_filter_config.go` - `MakeExtAuthzContextExtensions()` for route context
- `config/envoyconfig/routes.go:283-339` - Route ID and per-filter config setup
- `authorize/grpc.go:201-227` - `getEvaluatorRequestFromCheckRequest()` route context extraction
- `config/envoyconfig/luascripts/set-client-certificate-metadata.lua` - Dynamic metadata pattern

## Log

- 2026-02-02: Expanded with go-control-plane integration details and route context propagation
- 2026-02-02: Added complete ext_proc server implementation skeleton
- 2026-02-02: Documented three options for route context propagation (ext_authz metadata recommended)
- 2026-02-02: Confirmed ext_proc as the decided approach for response interception
- 2026-02-02: Issue created to document future response interception capability
