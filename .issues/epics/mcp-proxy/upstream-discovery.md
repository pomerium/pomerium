---
id: upstream-discovery
title: "Upstream Authorization Server Discovery"
status: open
created: 2026-01-26
updated: 2026-02-05
priority: high
labels:
  - mcp
  - proxy
  - discovery
  - rfc9728
  - rfc8414
  - ext_proc
deps:
  - route-configuration-schema
  - response-interception-implementation
---

# Upstream Authorization Server Discovery

## Summary

Implement automatic discovery of remote MCP server authorization requirements using RFC 9728 (Protected Resource Metadata) and RFC 8414 (Authorization Server Metadata). Discovery is **reactive**: triggered by intercepting 401 `WWW-Authenticate` responses from upstream via ext_proc, exactly as the MCP specification describes.

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

> **Section: Scope Challenge Handling**
> "When a protected resource returns a `403 Forbidden` with a `WWW-Authenticate` header containing `error="insufficient_scope"` and a `scope` parameter, the scope from the `WWW-Authenticate` header takes priority over `scopes_supported` from the Protected Resource Metadata."

### RFC 9728 - Protected Resource Metadata (/.docs/RFC/rfc9728.txt)

> **Section 5.1 - WWW-Authenticate Response**: The resource server indicates the protected resource metadata URL using the `resource_metadata` parameter in the `WWW-Authenticate` header.

> **Section 4 - Protected Resource Metadata**: Required fields include `resource` (the identifier) and `authorization_servers` (array of AS issuer URLs).

### RFC 8414 - AS Metadata (/.docs/RFC/rfc8414.txt)

> **Section 2 - Metadata**: Key fields include `authorization_endpoint`, `token_endpoint`, `response_types_supported`, `code_challenge_methods_supported`.

## Design: Reactive Discovery via ext_proc

### Why Reactive

The MCP spec's discovery mechanism is inherently reactive: the upstream returns a 401 with `WWW-Authenticate`, and the client uses that to discover authorization requirements. With ext_proc now scaffolded and merged (commit 968b0a36f), Pomerium can intercept these 401 responses and implement discovery exactly as the spec intends.

**Advantages over the previous proactive model:**

| Aspect | Proactive (old) | Reactive (new) |
|--------|-----------------|----------------|
| Discovery trigger | Probe well-known endpoints on `initialize` | 401 response from upstream |
| Non-OAuth detection | 404 on well-known = infer "no auth" | 200 from upstream = implicit, zero overhead |
| Scope hints | Only `scopes_supported` from metadata | `scope` param in WWW-Authenticate (priority per MCP spec) |
| Step-up auth | Not possible | 403 `insufficient_scope` handled naturally |
| Special methods | `initialize` treated specially | Any request triggers discovery |
| Spec compliance | Workaround (probes before forwarding) | Exact match to MCP spec flow |
| Extra round-trips | Always probes well-known, even for non-OAuth upstreams | None for non-OAuth upstreams |

### Component Responsibilities

```
┌──────────────────────────────────────────────────────────┐
│                   Discovery Architecture                  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ext_authz (request path)          ext_proc (response path)
│  ┌────────────────────────┐        ┌────────────────────┐│
│  │ 1. Check token cache   │        │ 1. Intercept 401   ││
│  │ 2. If token: inject it │        │ 2. Parse WWW-Auth  ││
│  │ 3. If no token +       │        │ 3. Fetch PRM       ││
│  │    cached discovery:   │        │ 4. Fetch AS Meta   ││
│  │    redirect early      │        │ 5. Cache discovery  ││
│  │ 4. If no token +       │        │ 6. Return redirect  ││
│  │    no discovery cache: │        │                    ││
│  │    forward as-is       │        │ Also handles:      ││
│  └────────────────────────┘        │ - 403 step-up auth ││
│                                    │ - Token refresh     ││
│                                    │   on expired tokens ││
│                                    └────────────────────┘│
│                                                          │
│              ┌─────────────────────────┐                 │
│              │   Shared Discovery Cache │                 │
│              │   (per upstream URL)     │                 │
│              └─────────────────────────┘                 │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## Discovery Flow

### First Request (No Cached Token, No Discovery Cache)

```
┌──────────┐    ┌──────────┐    ┌─────────┐    ┌──────────┐    ┌──────────┐
│MCP Client│    │ ext_authz│    │ ext_proc│    │ Upstream │    │Remote AS │
└────┬─────┘    └────┬─────┘    └────┬────┘    └────┬─────┘    └────┬─────┘
     │               │              │              │              │
     │ 1. MCP request│              │              │              │
     │──────────────>│              │              │              │
     │               │              │              │              │
     │               │ 2. No upstream token,       │              │
     │               │    no discovery cache        │              │
     │               │    → forward as-is           │              │
     │               │─────────────────────────────>│              │
     │               │              │              │              │
     │               │              │ 3. 401 Unauthorized         │
     │               │              │    WWW-Authenticate: Bearer │
     │               │              │      resource_metadata=     │
     │               │              │      "https://upstream/     │
     │               │              │       .well-known/          │
     │               │              │       oauth-protected-      │
     │               │              │       resource"             │
     │               │              │<─────────────│              │
     │               │              │              │              │
     │               │              │ 4. Parse WWW-Authenticate   │
     │               │              │    Extract resource_metadata│
     │               │              │              │              │
     │               │              │ 5. Fetch Protected Resource │
     │               │              │    Metadata (RFC 9728)      │
     │               │              │─────────────>│              │
     │               │              │<─────────────│              │
     │               │              │ {authorization_servers,     │
     │               │              │  scopes_supported}          │
     │               │              │              │              │
     │               │              │ 6. Fetch AS Metadata        │
     │               │              │    (RFC 8414)               │
     │               │              │────────────────────────────>│
     │               │              │<────────────────────────────│
     │               │              │ {authorization_endpoint,    │
     │               │              │  token_endpoint,            │
     │               │              │  code_challenge_methods}    │
     │               │              │              │              │
     │               │              │ 7. Cache discovery results  │
     │               │              │    Mark upstream as         │
     │               │              │    "needs OAuth"            │
     │               │              │              │              │
     │ 8. ImmediateResponse: 302    │              │              │
     │    Location: {auth_endpoint} │              │              │
     │    ?client_id=...&scope=...  │              │              │
     │<─────────────────────────────│              │              │
     │               │              │              │              │
     │ ... OAuth flow with Remote AS ...           │              │
     │ ... Pomerium callback, code→token exchange  │              │
     │ ... Token cached as (user, route, upstream)  │              │
     │               │              │              │              │
     │ 9. MCP request│              │              │              │
     │    (retry)    │              │              │              │
     │──────────────>│              │              │              │
     │               │              │              │              │
     │               │ 10. Token found in cache    │              │
     │               │     Inject Authorization:   │              │
     │               │     Bearer <token>           │              │
     │               │─────────────────────────────>│              │
     │               │              │              │              │
     │               │              │ 11. 200 OK   │              │
     │               │              │ (pass through)              │
     │<──────────────────────────────│<─────────────│              │
     │               │              │              │              │
```

### Subsequent Users (Discovery Cached, No Token)

After the first discovery, ext_authz knows this upstream needs OAuth and can redirect immediately without the round-trip to upstream:

```
┌──────────┐    ┌──────────┐    ┌──────────┐
│MCP Client│    │ ext_authz│    │ Upstream │
│(new user)│    │          │    │ MCP Server│
└────┬─────┘    └────┬─────┘    └────┬─────┘
     │               │              │
     │ 1. MCP request│              │
     │──────────────>│              │
     │               │              │
     │               │ 2. No upstream token,
     │               │    BUT discovery cache says
     │               │    "needs OAuth"
     │               │    → redirect immediately
     │               │              │
     │ 3. 302 → AS   │              │
     │    auth endpoint              │
     │<──────────────│              │
     │               │              │
     │ (no round-trip to upstream)  │
```

This optimization avoids the extra request-401-redirect cycle for every new user after the first discovery.

### Non-OAuth Upstreams

No discovery overhead at all. Upstream returns 200, ext_proc passes through:

```
┌──────────┐    ┌──────────┐    ┌─────────┐    ┌──────────┐
│MCP Client│    │ ext_authz│    │ ext_proc│    │ Upstream │
└────┬─────┘    └────┬─────┘    └────┬────┘    └────┬─────┘
     │               │              │              │
     │ 1. MCP request│              │              │
     │──────────────>│              │              │
     │               │              │              │
     │               │ 2. No token, no discovery   │
     │               │    cache → forward as-is    │
     │               │─────────────────────────────>│
     │               │              │              │
     │               │              │ 3. 200 OK    │
     │               │              │ (pass through)
     │<──────────────────────────────│<─────────────│
     │               │              │              │
```

### Token Expiry Mid-Session

When a cached token expires, ext_proc intercepts the resulting 401 and attempts refresh:

```
┌──────────┐    ┌──────────┐    ┌─────────┐    ┌──────────┐    ┌──────────┐
│MCP Client│    │ ext_authz│    │ ext_proc│    │ Upstream │    │Remote AS │
└────┬─────┘    └────┬─────┘    └────┬────┘    └────┬─────┘    └────┬─────┘
     │               │              │              │              │
     │ 1. MCP request│              │              │              │
     │──────────────>│              │              │              │
     │               │              │              │              │
     │               │ 2. Cached token found       │              │
     │               │    (expired, but ext_authz  │              │
     │               │     may not know)            │              │
     │               │    Inject Authorization      │              │
     │               │─────────────────────────────>│              │
     │               │              │              │              │
     │               │              │ 3. 401 (token expired)      │
     │               │              │<─────────────│              │
     │               │              │              │              │
     │               │              │ 4. User HAS cached token    │
     │               │              │    → check for refresh token│
     │               │              │              │              │
   ┌─┴──────────────────────────────┴──────────────────────────────┐
   │ BRANCH: Refresh Token Available?                               │
   ├────────────────────────────────────────────────────────────────┤
   │                                                                │
   │ A) Refresh token exists                                        │
   │    → ext_proc calls token endpoint with refresh_token grant    │
   │    → If refresh succeeds:                                      │
   │        Cache new token                                         │
   │        Return 302 back to original URL (client retries,        │
   │        ext_authz finds fresh token)                            │
   │    → If refresh fails (e.g. revoked):                          │
   │        Clear cached tokens                                     │
   │        Return 302 → authorization endpoint (full re-auth)      │
   │                                                                │
   │ B) No refresh token                                            │
   │    → Clear cached token                                        │
   │    → Return 302 → authorization endpoint (full re-auth)        │
   │                                                                │
   └────────────────────────────────────────────────────────────────┘
```

### Step-Up Authorization (403 insufficient_scope)

```
┌──────────┐    ┌──────────┐    ┌─────────┐    ┌──────────┐
│MCP Client│    │ ext_authz│    │ ext_proc│    │ Upstream │
└────┬─────┘    └────┬─────┘    └────┬────┘    └────┬─────┘
     │               │              │              │
     │ 1. MCP request│              │              │
     │──────────────>│              │              │
     │               │              │              │
     │               │ 2. Inject cached token      │
     │               │─────────────────────────────>│
     │               │              │              │
     │               │              │ 3. 403 Forbidden
     │               │              │    WWW-Authenticate: Bearer
     │               │              │      error="insufficient_scope"
     │               │              │      scope="mcp:read mcp:admin"
     │               │              │<─────────────│
     │               │              │              │
     │               │              │ 4. Parse scope from
     │               │              │    WWW-Authenticate
     │               │              │    (takes priority over
     │               │              │     scopes_supported)
     │               │              │              │
     │ 5. 302 → AS auth endpoint   │              │
     │    ?scope=mcp:read+mcp:admin│              │
     │<─────────────────────────────│              │
     │               │              │              │
     │ ... user re-authorizes with expanded scopes ...
```

## WWW-Authenticate Parsing

ext_proc must parse the `WWW-Authenticate` header per RFC 9728 §5.1 and RFC 6750 §3.

### Existing Codebase Pattern

Pomerium already uses `github.com/shogo82148/go-sfv` (Structured Field Values, RFC 8941) for WWW-Authenticate headers:

- **Encoding**: [handler_metadata.go:215-228](internal/mcp/handler_metadata.go#L215-L228) builds `Bearer resource_metadata="..."` via `sfv.EncodeDictionary()`
- **Decoding**: [mcp_auth_flow_test.go:293-313](internal/mcp/e2e/mcp_auth_flow_test.go#L293-L313) parses `resource_metadata` via `sfv.DecodeDictionary()`

The ext_proc parser MUST use the same `go-sfv` library to ensure round-trip compatibility.

### Parsing Implementation

```go
// ParseWWWAuthenticate parses a Bearer WWW-Authenticate header using go-sfv.
// Returns nil if the header is missing or not a Bearer challenge.
func ParseWWWAuthenticate(header string) *WWWAuthenticateParams {
    if !strings.HasPrefix(header, "Bearer ") {
        return nil
    }

    dict, err := sfv.DecodeDictionary([]string{strings.TrimPrefix(header, "Bearer ")})
    if err != nil {
        return nil
    }

    params := &WWWAuthenticateParams{}
    for _, member := range dict {
        if s, ok := member.Item.Value.(string); ok {
            switch member.Key {
            case "resource_metadata":
                params.ResourceMetadata = s
            case "scope":
                params.Scope = strings.Fields(s)
            case "error":
                params.Error = s
            case "error_description":
                params.ErrorDescription = s
            case "realm":
                params.Realm = s
            }
        }
    }
    return params
}
```

### Expected Format

```
WWW-Authenticate: Bearer
  realm="mcp-server",
  resource_metadata="https://upstream/.well-known/oauth-protected-resource",
  scope="mcp:read mcp:write",
  error="insufficient_scope",
  error_description="Token does not have required scope"
```

### Extracted Parameters

| Parameter | Usage | Priority |
|-----------|-------|----------|
| `resource_metadata` | URL to fetch Protected Resource Metadata (preferred over well-known probing) | Primary discovery source |
| `scope` | Required scopes for this request | **Priority over** `scopes_supported` from PRM (per MCP spec) |
| `error` | Error type (`insufficient_scope` triggers step-up auth) | Determines 401 vs 403 handling |
| `error_description` | Human-readable error for logging | Debugging only |
| `realm` | Resource realm | Informational |

### Fallback When `resource_metadata` Is Absent

Per MCP spec, servers MUST implement one of: WWW-Authenticate with `resource_metadata` OR well-known URI. If a 401 lacks `resource_metadata`:

```
1. ext_proc receives 401 without resource_metadata
2. Fall back to well-known URI probing:
   GET {upstream}/.well-known/oauth-protected-resource/{path}
   GET {upstream}/.well-known/oauth-protected-resource
3. If metadata found → continue with AS discovery
4. If not found → pass through 401 to client (non-compliant upstream)
```

## Protected Resource Metadata (RFC 9728)

Parse the following from the metadata endpoint (either from `resource_metadata` URL or well-known fallback):

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
- `grant_types_supported` MUST include `authorization_code`

## ext_authz Optimization: Cached Discovery Short-Circuit

After ext_proc performs the first discovery for an upstream, the results are stored in a shared cache. ext_authz can use this cache to redirect tokenless users immediately, avoiding the extra round-trip to upstream.

### ext_authz Request-Path Logic

```
func handleMCPRequest(user, route, upstream):
    // 1. Check upstream token cache
    token = tokenCache.get(user, route, upstream)

    if token != nil && !token.nearExpiry():
        // Happy path: inject token and forward
        injectAuthorizationHeader(token)
        return CONTINUE

    if token != nil && token.nearExpiry() && token.hasRefreshToken():
        // Proactive refresh before expiry
        newToken = refreshToken(token)
        if newToken != nil:
            injectAuthorizationHeader(newToken)
            return CONTINUE
        // Refresh failed — fall through, let ext_proc handle the 401

    // 2. Check discovery cache
    discovery = discoveryCache.get(upstream)

    if discovery != nil && discovery.authRequired:
        // We know this upstream needs OAuth and user has no token
        // → redirect immediately (skip the round-trip to upstream)
        return redirectToAuthorizationEndpoint(discovery, user, route)

    // 3. No token, no discovery cache (or discovery says no auth needed)
    // → forward as-is, let ext_proc handle any 401
    return CONTINUE
```

### Cache Structure

```go
// DiscoveryCache stores discovery results per upstream URL
type DiscoveryCache struct {
    // Key: upstream server URL (normalized)
    // Value: DiscoveryResult
}

type DiscoveryResult struct {
    // AuthRequired indicates the upstream returned a 401 with valid
    // discovery metadata. False means we've seen 200s from this upstream.
    AuthRequired bool

    // Populated when AuthRequired is true:
    ResourceMetadataURL string              // From WWW-Authenticate resource_metadata
    ProtectedResource   *ProtectedResource  // Parsed RFC 9728 metadata
    AuthorizationServer *ASMetadata         // Parsed RFC 8414 metadata
    ScopeHint           []string            // From WWW-Authenticate scope param

    // Cache control
    FetchedAt  time.Time
    ExpiresAt  time.Time  // Respects HTTP cache headers, max 1 hour
}
```

## Implementation Details

### Proposed Location

Create new file: `internal/mcp/upstream_discovery.go`

```go
// UpstreamDiscovery handles RFC 9728 and RFC 8414 discovery for remote MCP servers.
// Discovery is triggered reactively by ext_proc on 401 responses, or used by
// ext_authz to short-circuit redirect for cached upstreams.
type UpstreamDiscovery struct {
    httpClient *http.Client
    cache      *DiscoveryCache
}

// DiscoverFromWWWAuthenticate performs discovery starting from a parsed
// WWW-Authenticate header. This is the primary entry point, called by ext_proc.
func (d *UpstreamDiscovery) DiscoverFromWWWAuthenticate(
    ctx context.Context,
    upstreamURL string,
    wwwAuth *WWWAuthenticateHeader,
) (*DiscoveryResult, error)

// DiscoverFromWellKnown performs discovery by probing well-known endpoints.
// This is the fallback when WWW-Authenticate lacks resource_metadata.
func (d *UpstreamDiscovery) DiscoverFromWellKnown(
    ctx context.Context,
    upstreamURL string,
) (*DiscoveryResult, error)

// GetCached returns cached discovery results for an upstream, or nil.
// Called by ext_authz for the short-circuit optimization.
func (d *UpstreamDiscovery) GetCached(upstreamURL string) *DiscoveryResult
```

### Integration Points

1. **ext_proc `handleResponseHeaders()`** — calls `DiscoverFromWWWAuthenticate()` on 401, `DiscoverFromWellKnown()` as fallback
2. **ext_authz request handling** — calls `GetCached()` to short-circuit redirect for tokenless users
3. **Authorization choreographer** — receives discovery results to build OAuth redirect URLs
4. **Token handler** — uses cached AS metadata for token refresh

### Discovery Coalescing

Multiple concurrent 401s for the same upstream should not trigger parallel discovery requests. Use `singleflight.Group`:

```go
type UpstreamDiscovery struct {
    httpClient *http.Client
    cache      *DiscoveryCache
    inflight   singleflight.Group  // Coalesce concurrent discovery for same upstream
}

func (d *UpstreamDiscovery) DiscoverFromWWWAuthenticate(ctx context.Context, upstreamURL string, wwwAuth *WWWAuthenticateHeader) (*DiscoveryResult, error) {
    result, err, _ := d.inflight.Do(upstreamURL, func() (any, error) {
        return d.doDiscover(ctx, upstreamURL, wwwAuth)
    })
    return result.(*DiscoveryResult), err
}
```

## Implementation Tasks

### ext_proc 401 Response Handling
- [ ] Detect 401 status code in `handleResponseHeaders()`
- [ ] Extract and parse `WWW-Authenticate` header
- [ ] Extract `resource_metadata` URL (primary discovery source)
- [ ] Extract `scope` parameter (priority scope hints per MCP spec)
- [ ] If `resource_metadata` present: fetch Protected Resource Metadata from that URL
- [ ] If `resource_metadata` absent: fall back to well-known URI probing
- [ ] Fetch AS Metadata from discovered `authorization_servers`
- [ ] Cache discovery results
- [ ] Return `ImmediateResponse` redirect to authorization endpoint

### ext_proc 403 Response Handling
- [ ] Detect 403 status code in `handleResponseHeaders()`
- [ ] Check for `error="insufficient_scope"` in `WWW-Authenticate`
- [ ] Extract expanded `scope` parameter
- [ ] Return `ImmediateResponse` redirect with expanded scope request

### ext_proc Token Refresh on 401
- [ ] Detect 401 when user already has a cached token (expired)
- [ ] Check for refresh token availability
- [ ] Attempt token refresh via token endpoint
- [ ] On success: cache new token, return 302 back to original URL
- [ ] On failure: clear cached tokens, return 302 to authorization endpoint

### WWW-Authenticate Header Parsing (using `go-sfv`)
- [ ] Parse Bearer scheme using `sfv.DecodeDictionary()` (matches existing encoding pattern)
- [ ] Extract: `realm`, `error`, `error_description`, `scope`, `resource_metadata`
- [ ] Handle non-Bearer schemes (skip), missing header (nil), malformed SFV (nil)
- [ ] Unit tests for various WWW-Authenticate formats

### Protected Resource Metadata (RFC 9728)
- [ ] Fetch from `resource_metadata` URL (primary path)
- [ ] Fetch from `/.well-known/oauth-protected-resource/{path}` (fallback)
- [ ] Fetch from `/.well-known/oauth-protected-resource` (root fallback)
- [ ] Validate required fields: `resource`, `authorization_servers`
- [ ] Extract `scopes_supported` for scope selection strategy

### Authorization Server Metadata (RFC 8414)
- [ ] Fetch with MCP-specified priority order:
  - `{as}/.well-known/oauth-authorization-server/{path}`
  - `{as}/.well-known/openid-configuration/{path}`
  - `{as}/{path}/.well-known/openid-configuration`
- [ ] Validate PKCE support: `code_challenge_methods_supported` MUST include "S256"
- [ ] Detect CIMD support from `client_id_metadata_document_supported`
- [ ] Validate `grant_types_supported` includes `authorization_code`

### ext_authz Short-Circuit Optimization
- [ ] Check discovery cache in ext_authz request path
- [ ] If upstream "needs OAuth" and user has no token → redirect immediately
- [ ] If no discovery cache → forward as-is (ext_proc handles the 401)

### Discovery Caching
- [ ] Cache discovery results per upstream server URL (normalized)
- [ ] Respect HTTP cache headers (Cache-Control, Expires)
- [ ] Set max TTL (1 hour) even with permissive cache headers
- [ ] Invalidate on repeated authorization failures (upstream may have reconfigured)
- [ ] Coalesce concurrent discovery requests with `singleflight.Group`

### Error Handling
- [ ] Handle network failures during metadata fetch (return clear error)
- [ ] Handle invalid/malformed JSON in metadata responses
- [ ] Handle missing required fields with specific error messages
- [ ] Return `invalid_client` error when CIMD not supported and no fallback
- [ ] 401 without `resource_metadata` and failed well-known probing → pass through 401
- [ ] Log discovery failures for debugging without exposing sensitive data

## Acceptance Criteria

1. **Reactive discovery** — 401 `WWW-Authenticate` from upstream triggers discovery via ext_proc
2. **`resource_metadata` URL** is the primary discovery source (preferred over well-known probing)
3. **Well-known fallback** — discovery works when 401 lacks `resource_metadata`
4. **Scope from WWW-Authenticate** takes priority over `scopes_supported` from metadata (per MCP spec)
5. **Step-up authorization** — 403 `insufficient_scope` triggers re-authorization with expanded scopes
6. **Token refresh** — expired token 401 attempts refresh before full re-auth
7. **ext_authz optimization** — cached discovery allows immediate redirect for tokenless users
8. **Discovery coalescing** — concurrent 401s for the same upstream share a single discovery request
9. **Non-OAuth upstreams** — zero overhead (200 passes through, no probing)
10. **Discovery caching** — results cached per upstream, respecting HTTP cache headers, max 1h TTL
11. **PKCE validation** — AS metadata `code_challenge_methods_supported` MUST include "S256"
12. **CIMD detection** — `client_id_metadata_document_supported` checked before proceeding

## Test Scenarios

### Reactive Discovery (ext_proc 401 Handling)

| Scenario | Expected Behavior |
|----------|-------------------|
| 401 with `resource_metadata` URL | Fetch PRM from URL, discover AS, cache, redirect |
| 401 without `resource_metadata` | Fall back to well-known probing, discover AS, cache, redirect |
| 401 without `resource_metadata`, 404 on all well-known | Pass through 401 to client |
| 401 without WWW-Authenticate header | Pass through 401 (non-standard auth) |
| Multiple concurrent 401s for same upstream | Single discovery request (singleflight) |
| AS with path-based issuer | Try all three well-known endpoints in MCP order |
| PKCE not supported by AS | Fail with clear error (MCP requires PKCE) |
| CIMD not supported by AS | Log warning, fail (no fallback) |
| Network timeout during metadata fetch | Pass through 401, don't cache failure |

### ext_authz Short-Circuit

| Scenario | Expected Behavior |
|----------|-------------------|
| No discovery cache, no token | Forward as-is (ext_proc handles 401) |
| Discovery cache says "needs OAuth", no token | Redirect immediately (skip round-trip) |
| Discovery cache says "needs OAuth", has valid token | Inject token, forward |
| No discovery cache, upstream returns 200 | Pass through (non-OAuth upstream) |

### Token Expiry and Refresh

| Scenario | Expected Behavior |
|----------|-------------------|
| Expired token, refresh succeeds | Cache new token, 302 back to original URL |
| Expired token, refresh fails (revoked) | Clear cache, 302 to auth endpoint |
| Expired token, no refresh token | Clear cache, 302 to auth endpoint |
| Token near expiry in ext_authz | Proactive refresh before forwarding |

### Step-Up Authorization (403)

| Scenario | Expected Behavior |
|----------|-------------------|
| 403 with `error="insufficient_scope"`, `scope="mcp:admin"` | Redirect with expanded scope |
| 403 without `error="insufficient_scope"` | Pass through (not a scope issue) |
| 403 without WWW-Authenticate | Pass through |

### Non-OAuth Upstreams

| Scenario | Expected Behavior |
|----------|-------------------|
| Upstream returns 200 on first request | Pass through, zero discovery overhead |
| Pre-configured `upstream_headers` in route config | ext_authz injects headers, forward |
| Mix of OAuth and non-OAuth routes | Each route handled independently |

## References

- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](/.docs/RFC/rfc9728.txt)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](/.docs/RFC/rfc8414.txt)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](/.docs/RFC/rfc6750.txt) (WWW-Authenticate format)
- [MCP Authorization Spec](/.docs/mcp/basic/authorization.mdx) - Discovery requirements, Scope Challenge Handling
- [response-interception-implementation.md](./response-interception-implementation.md) - ext_proc scaffolding and server implementation
- [MCP Proxy Epic](./index.md)

## Log

- 2026-02-05: **MAJOR**: Rewrote for reactive discovery via ext_proc 401 interception; removed proactive well-known probing workaround; added ext_authz cached-discovery short-circuit optimization; added token refresh and step-up auth flows; added discovery coalescing via singleflight
- 2026-02-02: Changed to proactive discovery model via `initialize` interception (ext_authz cannot intercept responses); documented architectural constraint and future response interception enhancement
- 2026-02-02: Added support for non-OAuth upstreams per MCP spec "authorization is OPTIONAL"
- 2026-02-02: Added normative references, implementation reasoning, and test scenarios
- 2026-01-26: Issue created from epic breakdown
