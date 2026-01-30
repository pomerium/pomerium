---
id: authorization-choreographer
title: "Authorization Choreographer"
status: open
created: 2026-01-26
updated: 2026-01-26
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

## Requirements

From the epic:
> Handles the multi-step authorization flow:
> - Detects when upstream authorization is needed (401 from upstream, missing cached token)
> - Initiates OAuth 2.1 flow with remote AS (using PKCE, PAR if supported)
> - Manages user consent if remote AS requires it
> - Coordinates between client-facing session and upstream tokens

## Authorization Trigger Points

The choreographer must handle authorization in these scenarios:

1. **Cache Miss**: No cached token exists for (user_id, route_id, upstream_server) key
2. **Token Expired**: Cached access token has expired (and refresh fails)
3. **401 Response**: Upstream returns HTTP 401 Unauthorized
4. **Insufficient Scope**: Upstream returns 403 with `insufficient_scope` error

## State Machine

```
┌──────────────┐
│  No Token    │─────────────────────────────────┐
└──────────────┘                                 │
       │                                         │
       ▼                                         ▼
┌──────────────┐      ┌──────────────┐    ┌──────────────┐
│  Discovery   │─────>│  Auth Init   │───>│  Redirect    │
└──────────────┘      └──────────────┘    │  to AS       │
                             ▲            └──────────────┘
                             │                   │
                             │                   ▼
┌──────────────┐      ┌──────────────┐    ┌──────────────┐
│  Token Valid │<─────│  Token       │<───│  Callback    │
└──────────────┘      │  Exchange    │    │  Received    │
       │              └──────────────┘    └──────────────┘
       │
       ▼
┌──────────────┐
│  Forward     │
│  Request     │
└──────────────┘
```

## Authorization State

Track pending authorizations:

```go
type PendingAuthorization struct {
    ID              string
    UserID          string    // User to bind token to
    SessionID       string    // Session that initiated the flow (for resuming original request)
    RouteID         string
    UpstreamServer  string

    // OAuth state
    State           string
    CodeVerifier    string    // PKCE
    Nonce           string
    RedirectURI     string

    // Original request
    OriginalRequest *http.Request

    // Discovery results
    AuthorizationEndpoint string
    TokenEndpoint         string
    Scopes                []string

    CreatedAt       time.Time
    ExpiresAt       time.Time
}
```

## Implementation Tasks

### Flow Detection
- [ ] Intercept requests to proxy routes
- [ ] Check token cache for valid upstream token
- [ ] Handle 401 responses from upstream
- [ ] Handle insufficient_scope responses

### Authorization Initiation
- [ ] Generate secure state parameter
- [ ] Generate PKCE code_verifier and code_challenge
- [ ] Construct authorization URL with:
  - `client_id` (CIMD URL)
  - `redirect_uri` (callback URL)
  - `response_type=code`
  - `state`
  - `code_challenge` and `code_challenge_method`
  - `scope` (from discovery)
  - `resource` (upstream server URL per RFC 8707)
- [ ] Store pending authorization state

### User Redirect
- [ ] Return redirect response to user's browser
- [ ] Handle MCP protocol-specific redirect (if needed)
- [ ] Support both browser-based and programmatic redirects

### Callback Handling
- [ ] Validate state parameter
- [ ] Handle authorization errors from AS
- [ ] Extract authorization code
- [ ] Retrieve pending authorization state
- [ ] Trigger token exchange

### Token Exchange Coordination
- [ ] Call token endpoint with authorization code
- [ ] Include PKCE code_verifier
- [ ] Store acquired tokens
- [ ] Clean up pending authorization state
- [ ] Resume original request

### Error Handling
- [ ] Handle user denial of consent
- [ ] Handle AS errors
- [ ] Handle expired pending authorizations
- [ ] Provide meaningful error messages to users

## Acceptance Criteria

1. Missing token triggers authorization flow
2. 401 from upstream triggers re-authorization
3. State parameter prevents CSRF
4. PKCE is used for all authorization requests
5. Pending authorizations expire appropriately
6. Original request is resumed after successful authorization
7. User-facing errors are clear and actionable
8. Multiple concurrent authorization flows are handled correctly

## Security Considerations

- State parameter MUST be cryptographically random
- PKCE MUST be used (no plain challenge)
- Pending authorizations MUST expire
- Code verifier MUST remain server-side only

## References

- [OAuth 2.1 Draft](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [RFC 7636 - PKCE](/.docs/RFC/rfc7636.txt)
- [MCP Proxy Epic](./index.md)

## Log

- 2026-01-26: Clarified token cache key uses user_id (tokens bound to user only)
- 2026-01-26: Issue created from epic breakdown
