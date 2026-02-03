---
id: upstream-discovery
title: "Upstream Authorization Server Discovery"
status: open
created: 2026-01-26
updated: 2026-02-02
priority: high
labels:
  - mcp
  - proxy
  - discovery
  - rfc9728
  - rfc8414
deps:
  - route-configuration-schema
---

# Upstream Authorization Server Discovery

## Summary

Implement automatic discovery of remote MCP server authorization requirements using RFC 9728 (Protected Resource Metadata) and RFC 8414 (Authorization Server Metadata). This enables Pomerium to connect to any compliant MCP server without pre-configuration.

## Normative References

### MCP Authorization Spec (/.docs/mcp/basic/authorization.mdx)

> **Section: Protocol Requirements**
> "Authorization is **OPTIONAL** for MCP implementations. When supported:
> - Implementations using an HTTP-based transport **SHOULD** conform to this specification.
> - Implementations using an STDIO transport **SHOULD NOT** follow this specification, and instead retrieve credentials from the environment."

> **Section: Discovery Failure Handling (Sequence Diagram)**
> When Protected Resource Metadata is not found: "Abort or use pre-configured values"

> **Section: Authorization Server Location**
> "MCP servers **MUST** implement the OAuth 2.0 Protected Resource Metadata (RFC9728) specification to indicate the locations of authorization servers. The Protected Resource Metadata document returned by the MCP server **MUST** include the `authorization_servers` field containing at least one authorization server."

> **Section: Protected Resource Metadata Discovery Requirements**
> "MCP servers **MUST** implement one of the following discovery mechanisms:
> 1. **WWW-Authenticate Header**: Include the resource metadata URL in the `WWW-Authenticate` HTTP header under `resource_metadata` when returning `401 Unauthorized` responses
> 2. **Well-Known URI**: Serve metadata at a well-known URI as specified in RFC9728"

> **Section: Authorization Server Metadata Discovery**
> "MCP clients **MUST** attempt multiple well-known endpoints when discovering authorization server metadata:
> For issuer URLs with path components:
> 1. `/.well-known/oauth-authorization-server/{path}`
> 2. `/.well-known/openid-configuration/{path}`
> 3. `/{path}/.well-known/openid-configuration`
> For issuer URLs without path:
> 1. `/.well-known/oauth-authorization-server`
> 2. `/.well-known/openid-configuration`"

### RFC 9728 - Protected Resource Metadata (/.docs/RFC/rfc9728.txt)

> **Section 5.1 - WWW-Authenticate Response**: The resource server indicates the protected resource metadata URL using the `resource_metadata` parameter in the `WWW-Authenticate` header.

> **Section 4 - Protected Resource Metadata**: Required fields include `resource` (the identifier) and `authorization_servers` (array of AS issuer URLs).

### RFC 8414 - AS Metadata (/.docs/RFC/rfc8414.txt)

> **Section 2 - Metadata**: Key fields include `authorization_endpoint`, `token_endpoint`, `response_types_supported`, `code_challenge_methods_supported`.

## Architectural Constraint: Request-Only Interception

### Current Limitation

Pomerium's Envoy integration uses ext_authz which can only intercept **requests**, not responses. This means:

- ❌ Cannot intercept 401 WWW-Authenticate responses from upstream
- ❌ Cannot implement reactive discovery (forward → receive 401 → discover)
- ❌ Upstream 401 responses would be sent directly to clients

**Implementing full response interception in Envoy is a major new module and is explicitly OUT OF SCOPE for this epic.**

### Workaround: Proactive Discovery via `initialize` Interception

Per MCP Lifecycle spec (/.docs/mcp/basic/lifecycle.mdx):
> "The initialization phase **MUST** be the first interaction between client and server."
> "The client **MUST** initiate this phase by sending an `initialize` request"

**Solution**: Intercept the `initialize` method in ext_authz and perform proactive discovery before forwarding to upstream.

```
┌─────────────┐     ┌────────────┐     ┌─────────────┐     ┌────────────┐
│ MCP Client  │     │  Pomerium  │     │  Upstream   │     │ Remote AS  │
│             │     │  ext_authz │     │  MCP Server │     │            │
└──────┬──────┘     └─────┬──────┘     └──────┬──────┘     └─────┬──────┘
       │                  │                   │                  │
       │ 1. initialize    │                   │                  │
       │  (JSON-RPC)      │                   │                  │
       │─────────────────>│                   │                  │
       │                  │                   │                  │
       │                  │ 2. PROACTIVE DISCOVERY               │
       │                  │    (before forwarding initialize)    │
       │                  │                   │                  │
       │                  │ 2a. Check token cache               │
       │                  │     for this (user, route, upstream) │
       │                  │                   │                  │
       │                  │ 2b. If no token: Probe upstream      │
       │                  │     GET /.well-known/oauth-protected-resource
       │                  │───────────────────>│                  │
       │                  │<───────────────────│                  │
       │                  │   (200 + metadata, or 404)           │
       │                  │                   │                  │
   ┌───┴───────────────────────────────────────────────────────────┐
   │ BRANCH: Discovery Result                                      │
   ├───────────────────────────────────────────────────────────────┤
   │                                                               │
   │ A) No OAuth Required (404 on well-known, or no authorization_servers)
   │    → Forward initialize directly, mark route as "no-auth"     │
   │                                                               │
   │ B) OAuth Required (got authorization_servers in metadata)     │
   │    → Check if user has valid token for this upstream          │
   │    → If yes: Forward initialize with token                    │
   │    → If no: Return redirect to user for OAuth consent flow    │
   │                                                               │
   └───────────────────────────────────────────────────────────────┘
       │                  │                   │                  │
       │ 3. (If OAuth needed and no token)    │                  │
       │    Redirect to AS                    │                  │
       │<─────────────────│                   │                  │
       │                  │                   │                  │
       │ ... OAuth flow happens ...           │                  │
       │                  │                   │                  │
       │ 4. Client retries│                   │                  │
       │    initialize    │                   │                  │
       │─────────────────>│                   │                  │
       │                  │                   │                  │
       │                  │ 5. Token exists, forward initialize  │
       │                  │───────────────────>│                  │
       │                  │<───────────────────│                  │
       │<─────────────────│                   │                  │
       │                  │                   │                  │
```

### Why `initialize` is the Right Interception Point

1. **Mandatory first call**: Per MCP spec, `initialize` MUST be the first interaction
2. **Happens once per session**: Discovery cost is amortized over the session
3. **Clear user context**: We have the authenticated user from Pomerium session
4. **Natural retry point**: If OAuth is needed, client will retry after consent
5. **Already intercepted**: ext_authz sees all requests, including `initialize`

### Future Enhancement: ext_proc Response Interception

**Decision**: We will use Envoy's **ext_proc** filter for response interception when this capability is implemented.

When ext_proc is implemented (out of scope for current epic):

- Move to reactive discovery model
- Intercept 401 WWW-Authenticate responses
- Trigger OAuth flow based on actual upstream response
- Better handling of step-up authorization (403 insufficient_scope)
- Parse scope hints from WWW-Authenticate (priority over scopes_supported)

See [future-response-interception.md](./future-response-interception.md) for full implementation details.

For now, proactive discovery via `initialize` provides the same functionality with current architecture.

## Implementation Reasoning

### Why Discovery is Critical for Zero-Configuration

The current implementation in [host_info.go](internal/mcp/host_info.go:175-191) requires explicit `upstream_oauth2` configuration:
```go
if oa := policy.MCP.GetServerUpstreamOAuth2(); oa != nil {
    info.Config = &oauth2.Config{
        ClientID:     oa.ClientID,
        // ... explicit endpoint configuration
    }
}
```

For auto-discovery mode (when `upstream_oauth2` is nil), we need to dynamically discover these endpoints from the upstream server.

### Proposed Implementation Location

Create new file: `internal/mcp/upstream_discovery.go`

```go
// UpstreamDiscovery handles RFC 9728 and RFC 8414 discovery for remote MCP servers
type UpstreamDiscovery struct {
    httpClient *http.Client
    cache      *DiscoveryCache
}

// DiscoveredEndpoints contains the discovered OAuth endpoints for an upstream
type DiscoveredEndpoints struct {
    Resource              string   // From Protected Resource Metadata
    AuthorizationServers  []string // From Protected Resource Metadata
    ScopesSupported       []string // From Protected Resource Metadata
    AuthorizationEndpoint string   // From AS Metadata
    TokenEndpoint         string   // From AS Metadata
    CIMDSupported         bool     // client_id_metadata_document_supported
    PKCERequired          bool     // code_challenge_methods_supported includes S256
}
```

### Integration with Existing Code

1. **HostInfo extension**: Add `GetDiscoveredEndpoints(host string)` to [host_info.go](internal/mcp/host_info.go)
2. **Token handler integration**: Modify [handler_token.go](internal/mcp/handler_token.go) to use discovered endpoints
3. **Authorization flow**: Wire into authorization choreographer

## Discovery Flow (Proactive Model)

Discovery is triggered **proactively** when the MCP `initialize` method is intercepted in ext_authz, **before** forwarding to upstream.

```
1. Intercept        → ext_authz receives MCP initialize request
   initialize         ↓
2. Check Cache      → Do we have discovery results for this upstream?
                      ↓
   ├─ Cache hit     → Use cached discovery result
   │                  ↓
   └─ Cache miss    → Probe upstream for authorization requirements
                      ↓
3. Probe Upstream   → Try well-known endpoints (we cannot rely on 401):
   (Proactive)        GET {upstream}/.well-known/oauth-protected-resource/{path}
                      GET {upstream}/.well-known/oauth-protected-resource
                      ↓
   ├─ 200 + metadata → OAuth required, parse authorization_servers
   │                   ↓
   └─ 404 / no AS    → No OAuth required, mark as "no-auth"
                      ↓
4. Extract AS       → If OAuth required, parse authorization_servers array
                      (MCP spec: "MUST include at least one authorization server")
                      ↓
5. Fetch AS Meta    → Per MCP spec, try in order:
                      GET {as}/.well-known/oauth-authorization-server/{path}
                      GET {as}/.well-known/openid-configuration/{path}
                      GET {as}/{path}/.well-known/openid-configuration
                      ↓
6. Cache Results    → Store for subsequent requests (respect HTTP cache headers)
                      Cache "no-auth" status if no OAuth required
```

**Note**: This proactive model differs from the MCP spec's reactive model (which assumes 401 interception). We probe well-known endpoints directly because we cannot intercept 401 responses from upstream.

## Protected Resource Metadata (RFC 9728)

Parse the following from upstream's Protected Resource Metadata:

```json
{
  "resource": "https://remote-mcp.provider.com",
  "authorization_servers": ["https://auth.provider.com"],
  "scopes_supported": ["mcp:read", "mcp:write"],
  "bearer_methods_supported": ["header"]
}
```

**Validation per RFC 9728 §4**:
- `resource` MUST be present and match the upstream URL
- `authorization_servers` MUST be present with at least one AS

## Authorization Server Metadata (RFC 8414)

Parse the following from the AS Metadata:

```json
{
  "issuer": "https://auth.provider.com",
  "authorization_endpoint": "https://auth.provider.com/authorize",
  "token_endpoint": "https://auth.provider.com/token",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "client_id_metadata_document_supported": true
}
```

**Validation per MCP spec**:
- `code_challenge_methods_supported` MUST include "S256" (MCP requires PKCE)
- `client_id_metadata_document_supported` SHOULD be true for zero-config

## Upstreams Without OAuth Requirements

Per MCP spec, authorization is **OPTIONAL**. Many MCP servers don't require OAuth because they:
- Use bundled API keys (e.g., internal services with pre-shared secrets)
- Rely on network-level security (private networks, mTLS)
- Are public read-only services
- Use alternative authentication mechanisms (API keys in headers)

### Detection Flow

```
1. Initial Request  → Unauthenticated MCP request to upstream
                      ↓
2. Response Check   → Did upstream return 401 Unauthorized?
                      ↓
   ├─ NO (2xx/3xx)  → Upstream does NOT require OAuth
   │                  → Forward requests without additional tokens
   │                  → (May use pre-configured auth from route config)
   │
   └─ YES (401)     → Check for WWW-Authenticate header
                      ↓
      ├─ No header  → Non-standard auth required
      │              → Use pre-configured values or fail
      │
      └─ Has header → Proceed with OAuth discovery flow
```

### Discovery Result Types

```go
type DiscoveryResult struct {
    // AuthRequired indicates whether the upstream requires OAuth authorization
    AuthRequired bool

    // If AuthRequired is true, these contain the discovered endpoints
    Endpoints *DiscoveredEndpoints

    // If AuthRequired is false, this may contain pre-configured auth
    PreConfiguredAuth *PreConfiguredAuth
}

type PreConfiguredAuth struct {
    // Headers to inject (e.g., {"X-API-Key": "..."})
    Headers map[string]string

    // Or use a specific token from config
    StaticToken string
}
```

### Pre-Configured Authentication

When discovery determines OAuth is not required, Pomerium should check route configuration for pre-configured authentication:

```yaml
# Example route config for non-OAuth upstream
routes:
  - from: https://mcp.example.com
    to: https://internal-mcp.corp.local
    mcp:
      server:
        # No upstream_oauth2 = auto-discovery mode
        # But upstream doesn't require OAuth, use static auth:
        upstream_headers:
          X-API-Key: "${INTERNAL_API_KEY}"
```

### Handling Ambiguous Cases

| Scenario | Detection | Action |
|----------|-----------|--------|
| 200 OK on first request | No 401 received | Mark as `AuthRequired: false`, forward directly |
| 401 without WWW-Authenticate | Non-standard auth | Check pre-configured auth, else fail |
| 401 with WWW-Authenticate but no resource_metadata | Partial RFC compliance | Try well-known URIs, else fail |
| 404 on all well-known URIs | No OAuth metadata | Mark as `AuthRequired: false`, check pre-configured |

## Implementation Tasks

### `initialize` Method Interception (ext_authz)
- [ ] Detect JSON-RPC `initialize` method in ext_authz request handling
- [ ] Extract upstream URL from route configuration
- [ ] Trigger proactive discovery before forwarding
- [ ] If OAuth required and no token: return redirect response to client
- [ ] If OAuth required and token exists: forward with Authorization header
- [ ] If no OAuth required: forward directly (optionally with pre-configured headers)

### Proactive Discovery (Well-Known Probing)
- [ ] Probe `/.well-known/oauth-protected-resource/{path}` endpoint
- [ ] Probe `/.well-known/oauth-protected-resource` (root) as fallback
- [ ] Handle 200 response with valid metadata → OAuth required
- [ ] Handle 404 response → No OAuth required (mark as "no-auth")
- [ ] Handle network errors gracefully (retry with backoff)

### Non-OAuth Upstream Detection
- [ ] Handle 404 on all well-known metadata endpoints → no OAuth
- [ ] Handle metadata without `authorization_servers` → no OAuth
- [ ] Support route-level `upstream_headers` configuration for API keys
- [ ] Cache "no auth required" status per upstream

### WWW-Authenticate Header Parsing (for future response interception)
**Note**: These are not used in the current proactive model but will be needed when response interception is implemented.
- [ ] Parse `resource_metadata` parameter from WWW-Authenticate (RFC 9728 §5.1)
- [ ] Parse `scope` parameter for required scopes (RFC 6750 §3)
- [ ] Parse `error` and `error_description` for debugging
- [ ] Handle Bearer scheme parsing with multiple parameters

### Protected Resource Metadata (RFC 9728)
- [ ] Implement metadata fetch from `resource_metadata` URL (preferred)
- [ ] Implement fallback to `/.well-known/oauth-protected-resource/{path}` (MCP spec)
- [ ] Implement fallback to `/.well-known/oauth-protected-resource` (root)
- [ ] Validate required fields: `resource`, `authorization_servers`
- [ ] Extract `scopes_supported` for scope selection strategy

### Authorization Server Metadata (RFC 8414)
- [ ] Implement AS metadata fetch with MCP-specified priority order
- [ ] Support path-based issuers: `/.well-known/oauth-authorization-server/{path}`
- [ ] Support OIDC discovery: `/.well-known/openid-configuration`
- [ ] Validate PKCE support: `code_challenge_methods_supported` MUST include "S256"
- [ ] Detect CIMD support from `client_id_metadata_document_supported`
- [ ] Validate `grant_types_supported` includes `authorization_code`

### Caching (per CIMD spec §4.4)
- [ ] Cache Protected Resource Metadata per upstream server URL
- [ ] Cache Authorization Server Metadata per AS issuer URL
- [ ] Respect HTTP cache headers (Cache-Control, Expires)
- [ ] Implement cache invalidation on authorization failures
- [ ] Set max TTL (e.g., 1 hour) even with permissive cache headers

### Error Handling
- [ ] Handle network failures during discovery (return clear error)
- [ ] Handle invalid/malformed JSON responses
- [ ] Handle missing required fields with specific error messages
- [ ] Return `invalid_client` error when CIMD not supported and no fallback
- [ ] Log discovery failures for debugging without exposing sensitive data

## Acceptance Criteria

1. **Discovery is triggered proactively** on `initialize` method interception (not waiting for 401)
2. Pomerium discovers authorization requirements from any RFC 9728-compliant server
3. Protected Resource Metadata is fetched via direct well-known endpoint probing
4. Authorization Server Metadata is fetched with MCP-specified priority
5. PKCE support (`S256`) is validated before proceeding
6. Discovery results are cached respecting HTTP cache headers
7. Cache invalidation works on subsequent authorization failures
8. Clear error when upstream doesn't support CIMD (`client_id_metadata_document_supported: false`)
9. **Upstreams that don't require OAuth are detected and handled correctly**
10. **Pre-configured auth (API keys, headers) is applied when specified**
11. **`initialize` method triggers OAuth redirect if token not present**

## Test Scenarios

### Initialize Interception Scenarios

| Scenario | Expected Behavior |
|----------|-------------------|
| `initialize` method detected in ext_authz | Trigger proactive discovery before forwarding |
| User has valid token for upstream | Forward `initialize` with Authorization header |
| User has no token, OAuth required | Return redirect to AS authorization endpoint |
| User has expired token, refresh succeeds | Forward `initialize` with refreshed token |
| User has expired token, refresh fails | Return redirect for re-authorization |
| Non-initialize method, no token | Also trigger discovery (any MCP method needs auth) |

### Proactive Discovery Scenarios (Well-Known Probing)

| Scenario | Expected Behavior |
|----------|-------------------|
| 200 on `/.well-known/oauth-protected-resource/{path}` | Parse metadata, OAuth required |
| 404 on path, 200 on root well-known | Parse root metadata, OAuth required |
| 404 on all well-known endpoints | No OAuth required, forward directly |
| Metadata without `authorization_servers` | No OAuth required (unusual but valid) |
| AS with path issuer | Try all three well-known endpoints in MCP order |
| PKCE not supported by AS | Fail with clear error (MCP requires PKCE) |
| CIMD not supported by AS | Log warning, fail (no fallback) |
| Network timeout during discovery | Return error, don't cache failure |

### Non-OAuth Upstream Scenarios

| Scenario | Expected Behavior |
|----------|-------------------|
| 404 on all well-known endpoints | Mark `AuthRequired: false`, forward directly |
| Pre-configured `upstream_headers` in route | Inject headers into forwarded requests |
| Upstream with bundled API key | Forward without additional tokens |
| Mix: Some routes OAuth, some not | Handle per-route based on discovery result |

## References

- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](/.docs/RFC/rfc9728.txt)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](/.docs/RFC/rfc8414.txt)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](/.docs/RFC/rfc6750.txt) (WWW-Authenticate format)
- [MCP Authorization Spec](/.docs/mcp/basic/authorization.mdx) - Discovery requirements
- [MCP Proxy Epic](./index.md)

## Log

- 2026-02-02: **MAJOR**: Changed to proactive discovery model via `initialize` interception (ext_authz cannot intercept responses); documented architectural constraint and future response interception enhancement
- 2026-02-02: Added support for non-OAuth upstreams per MCP spec "authorization is OPTIONAL"
- 2026-02-02: Added normative references, implementation reasoning, and test scenarios
- 2026-01-26: Issue created from epic breakdown
