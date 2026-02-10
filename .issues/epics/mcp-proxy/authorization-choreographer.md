---
id: authorization-choreographer
title: "Authorization Choreographer"
status: open
created: 2026-01-26
updated: 2026-02-02
priority: high
labels:
  - mcp
  - proxy
  - oauth2
  - authorization
deps:
  - route-configuration-schema
  - upstream-discovery
  - per-route-cimd-hosting
  - upstream-token-storage
---

# Authorization Choreographer

## Summary

Implement the central coordinator for the multi-step upstream authorization flow. The choreographer detects when upstream authorization is needed, initiates OAuth 2.1 flows, and manages the authorization lifecycle.

## Normative References

### MCP Authorization Spec (/.docs/mcp/basic/authorization.mdx)

> **Section: Authorization Flow Steps (Sequence Diagram)**
> The complete authorization flow shows the client receiving 401, discovering metadata, performing CIMD registration, OAuth authorization, and then making authenticated requests.

> **Section: Scope Challenge Handling**
> "When a client makes a request with an access token with insufficient scope during runtime operations, the server **SHOULD** respond with:
> - `HTTP 403 Forbidden` status code
> - `WWW-Authenticate` header with... `error="insufficient_scope"`"

> **Section: Step-Up Authorization Flow**
> "Clients **SHOULD** respond to these errors by requesting a new access token with an increased set of scopes via a step-up authorization flow."

> **Section: Scope Selection Strategy**
> "MCP clients **SHOULD** follow this priority order for scope selection:
> 1. Use `scope` parameter from the initial `WWW-Authenticate` header in the 401 response, if provided
> 2. If `scope` is not available, use all scopes defined in `scopes_supported` from the Protected Resource Metadata document"

### OAuth 2.1 Draft (/.docs/RFC/draft-ietf-oauth-v2-1.txt)

> **Section 7.5.2**: PKCE prevents authorization code interception by requiring code_verifier on token exchange.
> **Section 7.12**: State parameter prevents CSRF attacks on redirect flow.

## Implementation Reasoning

### Why a Choreographer Pattern?

The upstream OAuth flow involves multiple asynchronous steps across different endpoints:
1. Request interception → 2. Discovery → 3. Authorization redirect → 4. Callback handling → 5. Token exchange → 6. Request forwarding

A choreographer centralizes this logic, making it:
- Testable (single point of coordination)
- Debuggable (clear state transitions)
- Maintainable (isolated from request handlers)

### Integration with Existing Code

The existing handlers provide building blocks:
- [handler_authorization.go](internal/mcp/handler_authorization.go): AS authorization flow (Pomerium as AS)
- [handler_oauth_callback.go](internal/mcp/handler_oauth_callback.go): Callback handling pattern
- [handler_token.go](internal/mcp/handler_token.go): Token exchange and refresh

For proxy mode, we need a parallel set of handlers/logic where Pomerium acts as client.

### Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authorization Choreographer                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Request   │    │  Discovery  │    │  OAuth      │         │
│  │ Interceptor │───>│   Service   │───>│  Client     │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│         │                                     │                 │
│         │                                     │                 │
│         ▼                                     ▼                 │
│  ┌─────────────┐                       ┌─────────────┐         │
│  │   Token     │                       │  Pending    │         │
│  │   Cache     │                       │  Auth State │         │
│  └─────────────┘                       └─────────────┘         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Authorization Trigger Points

Per MCP spec, the choreographer must handle authorization in these scenarios:

| Trigger | Detection | Action |
|---------|-----------|--------|
| Cache Miss | No token for (user, route, upstream) | Initiate authorization |
| Token Expired | Access token expired, refresh fails | Initiate re-authorization |
| 401 Unauthorized | Upstream returns 401 | Parse WWW-Authenticate, re-authorize |
| Insufficient Scope | Upstream returns 403 + `insufficient_scope` | Step-up authorization with new scopes |

## State Machine

```
┌──────────────┐
│  No Token    │─────────────────────────────────┐
└──────────────┘                                 │
       │                                         │
       ▼                                         ▼
┌──────────────┐      ┌──────────────┐    ┌──────────────┐
│  Discovery   │─────>│  Auth Init   │───>│  Redirect    │
│  (RFC 9728)  │      │  (PKCE gen)  │    │  to AS       │
└──────────────┘      └──────────────┘    └──────────────┘
                             ▲                   │
                             │                   │
                             │                   ▼
┌──────────────┐      ┌──────────────┐    ┌──────────────┐
│  Token Valid │<─────│  Token       │<───│  Callback    │
│  Forward Req │      │  Exchange    │    │  Received    │
└──────────────┘      └──────────────┘    └──────────────┘
```

## Pending Authorization State

Track pending authorizations in databroker (survives restarts):

```go
// PendingAuthorization represents an in-flight upstream OAuth flow
type PendingAuthorization struct {
    ID              string
    UserID          string    // User to bind token to (per-user binding)
    SessionID       string    // For resuming original request
    RouteID         string    // Route isolation
    UpstreamServer  string    // Resource being accessed

    // OAuth state (PKCE + CSRF)
    State           string    // Cryptographically random, validated on callback
    CodeVerifier    string    // PKCE secret, never transmitted except to token endpoint
    RedirectURI     string    // Must match exactly on token exchange

    // From discovery
    AuthorizationEndpoint string
    TokenEndpoint         string
    Scopes                []string  // Per MCP scope selection strategy
    Resource              string    // RFC 8707 resource indicator

    // Lifecycle
    CreatedAt       time.Time
    ExpiresAt       time.Time  // Short expiry - 10 minutes max
}
```

## Implementation Tasks

### Flow Detection
- [x] Intercept requests to auto-discovery proxy routes (ext_proc `handleResponseHeaders`)
- [x] Check token cache for valid upstream token (`getAutoDiscoveryToken` in upstream_auth.go)
- [x] If token exists and valid, inject via `injectAuthorizationHeader`
- [x] If no token or expired, forward request bare (upstream will return 401)
- [x] Handle 401 responses from upstream (parse WWW-Authenticate via `ParseWWWAuthenticate`)
- [x] Handle 403 + `insufficient_scope` (step-up authorization via same `handle401` path)

### Authorization Initiation (per MCP spec)
- [x] Trigger upstream discovery (RFC 9728 → RFC 8414) via `runDiscovery`
- [x] Apply MCP scope selection strategy (`selectScopes`):
  - First: `scope` from WWW-Authenticate
  - Fallback: `scopes_supported` from Protected Resource Metadata
- [x] Generate cryptographically random state (32+ bytes) via `generateRandomString`
- [x] Generate PKCE code_verifier and code_challenge (S256) via `generatePKCE`
- [x] Build authorization URL with all required parameters via `buildAuthorizationURL`
- [x] Store pending authorization in databroker via `PutPendingUpstreamAuth` + user+host index
- [x] Return 401 to MCP client (triggers re-auth via Pomerium's own OAuth flow)

### User Redirect (per MCP Authorization Flow)
- [x] Authorize endpoint detects pending upstream auth and redirects browser to AS authorization_endpoint
- [x] Include all required parameters (client_id, redirect_uri, scope, state, code_challenge, resource)
- [x] Support programmatic MCP clients via 401 + WWW-Authenticate → client re-runs MCP OAuth flow

### Callback Handling
- [x] Receive authorization code at redirect_uri (`ClientOAuthCallback`)
- [x] Validate state parameter (CSRF protection) via PendingUpstreamAuth lookup
- [x] Handle authorization errors from AS (`error`, `error_description`)
- [x] Look up pending authorization by state
- [x] Trigger token exchange via `exchangeToken`

### Token Exchange Coordination
- [x] Call token endpoint with code + code_verifier
- [x] Parse and validate token response
- [x] Store tokens with proper binding (user, route, upstream) via `PutUpstreamMCPToken`
- [x] Clean up pending authorization state + index
- [x] Complete MCP client OAuth flow via `AuthorizationResponse` (issues auth code to MCP client)

### Error Handling
- [x] User denies consent → Clear error message from AS error params
- [x] AS returns error → Parse and display/log appropriately
- [x] Pending auth expired → Restart flow (don't use stale state)
- [ ] Network error during discovery → Retry with backoff
- [ ] Multiple concurrent flows for same user/route → Deduplicate (singleflight)

## Scope Selection Implementation

Per MCP spec "Scope Selection Strategy":

```go
func selectScopes(wwwAuth *WWWAuthenticateHeader, prm *ProtectedResourceMetadata) []string {
    // Priority 1: scope from WWW-Authenticate header
    if wwwAuth != nil && len(wwwAuth.Scope) > 0 {
        return wwwAuth.Scope
    }

    // Priority 2: scopes_supported from Protected Resource Metadata
    if prm != nil && len(prm.ScopesSupported) > 0 {
        return prm.ScopesSupported
    }

    // Fallback: omit scope parameter (let AS decide)
    return nil
}
```

## Acceptance Criteria

1. Missing token triggers authorization flow automatically
2. 401 from upstream triggers re-authorization with discovered scopes
3. 403 + `insufficient_scope` triggers step-up authorization
4. State parameter prevents CSRF (validated on callback)
5. PKCE S256 is used for all authorization requests
6. Pending authorizations expire after 10 minutes
7. Original request context is preserved and resumed
8. User-facing errors are clear and actionable
9. Multiple concurrent flows for same context are deduplicated

## Security Considerations

Per MCP spec and OAuth 2.1:

| Requirement | Implementation | Spec Reference |
|-------------|----------------|----------------|
| State cryptographically random | `crypto/rand` 32+ bytes | OAuth 2.1 §7.12 |
| PKCE always used (S256) | Never plain, never optional | MCP Auth: MUST use S256 |
| Pending auth short-lived | 10 minute max expiry | Limit attack window |
| Code verifier server-side only | In databroker, never in redirect | OAuth 2.1 §7.5.2 |
| Tokens not logged | Mask in all logging | MCP Security |

## References

- [OAuth 2.1 Draft](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [MCP Authorization Spec](/.docs/mcp/basic/authorization.mdx) - Scope selection, step-up auth
- [MCP Proxy Epic](./index.md)
- Dependencies: [upstream-discovery](./upstream-discovery.md), [upstream-oauth-client-flow](./upstream-oauth-client-flow.md)
- Existing patterns: [handler_authorization.go](internal/mcp/handler_authorization.go)

## Log

- 2026-02-07: **MAJOR**: Core choreography implemented — ext_proc returns 401 to trigger MCP client re-auth; Authorize endpoint links pending upstream auth and redirects browser to upstream AS; ClientOAuthCallback completes MCP flow via AuthorizationResponse; implemented as `UpstreamAuthHandler` (upstream_auth.go) + Authorize endpoint integration (handler_authorization.go) + ClientOAuthCallback flow (handler_client_oauth_callback.go)
- 2026-02-02: Added normative references, scope selection implementation, architecture diagram
- 2026-01-26: Clarified token cache key uses user_id (tokens bound to user only)
- 2026-01-26: Issue created from epic breakdown
