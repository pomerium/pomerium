---
id: upstream-oauth-client-flow
title: "OAuth 2.1 Client Flow Implementation"
status: open
created: 2026-01-26
updated: 2026-02-02
priority: high
labels:
  - mcp
  - proxy
  - oauth2
  - pkce
deps:
  - upstream-discovery
  - per-route-cimd-hosting
---

# OAuth 2.1 Client Flow Implementation

## Summary

Implement the OAuth 2.1 Authorization Code flow with PKCE for Pomerium acting as an MCP client to remote authorization servers. This is the core OAuth client implementation used by the authorization choreographer.

## Normative References

### MCP Authorization Spec (/.docs/mcp/basic/authorization.mdx)

> **Section: Authorization Code Protection**
> "MCP clients **MUST** implement PKCE according to OAuth 2.1 Section 7.5.2 and **MUST** verify PKCE support before proceeding with authorization."

> **Section: PKCE Requirements**
> "MCP clients **MUST** use the `S256` code challenge method when technically capable, as required by OAuth 2.1 Section 4.1.1."

> **Section: Resource Parameter Implementation**
> "MCP clients **MUST** implement Resource Indicators for OAuth 2.0 as defined in RFC 8707... The `resource` parameter:
> 1. **MUST** be included in both authorization requests and token requests.
> 2. **MUST** identify the MCP server that the client intends to use the token with."

> **Section: Authorization Flow Steps (Sequence Diagram)**
> The spec shows: "Generate PKCE parameters, Include resource parameter, Apply scope selection strategy" before initiating authorization.

### OAuth 2.1 Draft (/.docs/RFC/draft-ietf-oauth-v2-1.txt)

> **Section 4.1.1**: PKCE `code_challenge_method` MUST be S256 unless AS doesn't support it.
> **Section 7.5.2**: Clients MUST use PKCE to protect against authorization code interception.

### RFC 8707 - Resource Indicators (/.docs/RFC/rfc8707.txt)

> **Section 2**: The `resource` parameter value MUST be an absolute URI.

## Implementation Reasoning

### Why This is the Core of the Proxy Flow

This OAuth client flow is the mechanism by which Pomerium acquires tokens from remote authorization servers. The existing code in [handler_authorization.go](internal/mcp/handler_authorization.go) handles Pomerium acting as an AS, but for proxy mode, Pomerium needs to act as an OAuth client.

### Existing Patterns to Leverage

The codebase already has token handling infrastructure:
- [token.go](internal/mcp/token.go:58-99): `GetUpstreamOAuth2Token()` with singleflight refresh
- [storage.go](internal/mcp/storage.go:171-233): Token storage/retrieval
- [host_info.go](internal/mcp/host_info.go:208-231): Token conversion helpers

### Proposed Implementation Location

Create new file: `internal/mcp/upstream_oauth_client.go`

```go
// UpstreamOAuthClient implements OAuth 2.1 client flow for remote AS
type UpstreamOAuthClient struct {
    httpClient    *http.Client
    storage       *Storage
    discovery     *UpstreamDiscovery
}

// StartAuthorization initiates an authorization flow to a remote AS
func (c *UpstreamOAuthClient) StartAuthorization(ctx context.Context, params AuthorizationParams) (*PendingAuthorization, error) {
    // 1. Generate PKCE: code_verifier (32 bytes random), code_challenge (SHA256)
    // 2. Generate state (cryptographically random)
    // 3. Build authorization URL with required parameters
    // 4. Store pending authorization state
    // 5. Return redirect URL
}

// ExchangeCode exchanges authorization code for tokens
func (c *UpstreamOAuthClient) ExchangeCode(ctx context.Context, code string, pending *PendingAuthorization) (*oauth2.Token, error) {
    // 1. Validate state matches
    // 2. POST to token endpoint with code + code_verifier
    // 3. Parse token response
    // 4. Store tokens with audience binding
}
```

## OAuth 2.1 Flow

```
┌──────────┐                                          ┌──────────────┐
│ Pomerium │                                          │  Remote AS   │
│ (Client) │                                          │              │
└────┬─────┘                                          └──────┬───────┘
     │                                                       │
     │ 1. Authorization Request                              │
     │    GET /authorize                                     │
     │    ?client_id={cimd_url}                             │
     │    &redirect_uri={callback}                          │
     │    &response_type=code                               │
     │    &state={random}                                   │
     │    &code_challenge={challenge}                       │
     │    &code_challenge_method=S256                       │
     │    &scope={scopes}                                   │
     │    &resource={upstream_server}  ← RFC 8707 REQUIRED  │
     │─────────────────────────────────────────────────────>│
     │                                                       │
     │ 2. User authenticates & consents                     │
     │                                                       │
     │ 3. Authorization Response                             │
     │    302 Redirect to callback                          │
     │    ?code={auth_code}                                 │
     │    &state={random}                                   │
     │<─────────────────────────────────────────────────────│
     │                                                       │
     │ 4. Token Request                                      │
     │    POST /token                                       │
     │    grant_type=authorization_code                     │
     │    &code={auth_code}                                 │
     │    &redirect_uri={callback}                          │
     │    &client_id={cimd_url}                             │
     │    &code_verifier={verifier}                         │
     │    &resource={upstream_server}  ← RFC 8707 REQUIRED  │
     │─────────────────────────────────────────────────────>│
     │                                                       │
     │ 5. Token Response                                     │
     │    {access_token, refresh_token, expires_in, ...}   │
     │<─────────────────────────────────────────────────────│
     │                                                       │
```

## PKCE Implementation (per MCP spec requirements)

Per MCP Authorization Spec: "MCP clients **MUST** use the `S256` code challenge method"

```go
// Generate code verifier (43-128 chars, unreserved URI chars)
// Per RFC 7636 Appendix B: RECOMMENDED 32 octets of random data
codeVerifier := base64.RawURLEncoding.EncodeToString(randomBytes(32))

// Generate code challenge (SHA256 of verifier, base64url encoded without padding)
hash := sha256.Sum256([]byte(codeVerifier))
codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
codeChallengeMethod := "S256"
```

## Required Authorization Parameters

Per MCP spec, all authorization requests MUST include:

| Parameter | Value | Spec Reference |
|-----------|-------|----------------|
| `client_id` | CIMD URL | CIMD spec §3 |
| `redirect_uri` | Callback URL | OAuth 2.1 §4.1.1 |
| `response_type` | `code` | OAuth 2.1 §4.1.1 |
| `state` | Random string | OAuth 2.1 §7.12 |
| `code_challenge` | S256 hash | MCP Auth: "MUST use S256" |
| `code_challenge_method` | `S256` | MCP Auth: "MUST use S256" |
| `scope` | From discovery | MCP Auth: Scope Selection Strategy |
| `resource` | Upstream URL | MCP Auth: "MUST be included" |

## Implementation Tasks

### PKCE (MCP spec: MUST use S256)
- [ ] Implement secure code verifier generation (32 bytes random, base64url)
- [ ] Implement S256 code challenge generation (SHA256, base64url no padding)
- [ ] Store code verifier in pending authorization state (server-side only)
- [ ] Never transmit code verifier except to token endpoint

### Authorization Request
- [ ] Build authorization URL with all required parameters (table above)
- [ ] Include `resource` parameter per RFC 8707 (MCP: MUST be included)
- [ ] Apply MCP scope selection strategy (WWW-Authenticate scope or scopes_supported)
- [ ] Generate cryptographically random state parameter
- [ ] Support `prompt` parameter for consent behavior

### Token Request
- [ ] POST to discovered token_endpoint
- [ ] Include authorization code
- [ ] Include code_verifier (PKCE completion)
- [ ] Include client_id (CIMD URL)
- [ ] Include redirect_uri (must match auth request exactly)
- [ ] Include resource parameter (same as auth request)
- [ ] Content-Type: application/x-www-form-urlencoded

### Token Response Handling
- [ ] Parse access_token (required)
- [ ] Parse refresh_token (optional but expected per MCP)
- [ ] Parse expires_in (calculate expiry time)
- [ ] Parse token_type (usually "Bearer")
- [ ] Parse scope (may differ from requested - granted scope)
- [ ] Handle error responses per OAuth 2.1 §5.2

### Refresh Token Flow (per MCP: "assumes short-lived access tokens and long-lived refresh tokens")
- [ ] Implement refresh_token grant type
- [ ] Include client_id in refresh request
- [ ] Include resource parameter in refresh request
- [ ] Handle refresh token rotation (store new refresh token)
- [ ] Handle refresh failures → trigger full re-authorization

### Error Handling (per OAuth 2.1 §5.2)
- [ ] Parse OAuth error responses from both endpoints
- [ ] Map errors to appropriate actions:
  - `invalid_grant` → Re-authorize (code expired or already used)
  - `invalid_client` → CIMD not supported or invalid
  - `access_denied` → User denied consent
  - `invalid_scope` → Use scopes_supported instead
  - `invalid_target` → Resource identifier invalid (RFC 8707)
- [ ] Provide actionable error messages

## Acceptance Criteria

1. Full OAuth 2.1 authorization code flow works end-to-end
2. PKCE S256 is always used (MCP requirement)
3. Resource indicator is included in both auth and token requests (MCP requirement)
4. Token response is parsed and stored with audience binding
5. Refresh token flow works including rotation
6. All OAuth errors are handled with appropriate fallback actions
7. No client secrets are used (public client via CIMD)

## Security Considerations

Per MCP Authorization Spec § Security Considerations:

| Requirement | Implementation |
|-------------|----------------|
| Code verifier cryptographically random | Use `crypto/rand` for 32 bytes |
| Code verifier server-side only | Store in pending auth state, never in redirect |
| State validated on callback | Compare with stored pending auth state |
| Tokens not logged | Use `zerolog` with sensitive field masking |
| PKCE mandatory | Fail authorization if AS doesn't support S256 |

## References

- [OAuth 2.1 Draft](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [RFC 8707 - Resource Indicators](/.docs/RFC/rfc8707.txt)
- [MCP Authorization Spec](/.docs/mcp/basic/authorization.mdx) - Primary normative reference
- [MCP Proxy Epic](./index.md)
- Existing patterns: [token.go](internal/mcp/token.go), [storage.go](internal/mcp/storage.go)

## Log

- 2026-02-02: Added normative references, required parameters table, implementation reasoning
- 2026-01-26: Issue created from epic breakdown
