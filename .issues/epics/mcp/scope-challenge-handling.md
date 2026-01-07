---
id: scope-challenge-handling
title: "Scope Challenge and Step-Up Authorization"
status: open
created: 2026-01-06
updated: 2026-01-07
priority: medium
labels:
  - mcp
  - oauth2
  - authorization
deps:
  - www-authenticate-header
---

# Scope Challenge and Step-Up Authorization

## Summary

Implement scope challenge handling for insufficient scope errors (HTTP 403) and support step-up authorization flows for incremental consent. This applies to both MCP-compliant upstream servers and legacy OAuth providers.

## Architecture Context

Pomerium supports two distinct upstream OAuth scenarios:

### Scenario A: Legacy OAuth Providers (Non-MCP)
Traditional OAuth providers (Google, GitHub, Microsoft, etc.) that:
- Don't implement MCP OAuth spec
- Don't support dynamic client registration
- Require pre-configured client credentials via `upstream_oauth2`

**Example**: Proxying to a tool that needs Google Drive API access

### Scenario B: MCP-Compliant Upstreams
MCP servers that implement:
- `/.well-known/oauth-protected-resource` discovery
- Proper scope challenge responses (403 with `insufficient_scope`)
- Support for Dynamic Client Registration or Client ID Metadata Documents

**Example**: Proxying to another MCP server that requires OAuth

**Note**: The `upstream_oauth2` configuration remains essential for Scenario A, while discovery-based approaches enable Scenario B. Both should be supported.

## Requirement (from MCP Specification)

> When a client makes a request with an access token with insufficient scope during runtime operations, the server **SHOULD** respond with:
>
> - `HTTP 403 Forbidden` status code (per RFC 6750 Section 3.1)
> - `WWW-Authenticate` header with the `Bearer` scheme and additional parameters:
>   - `error="insufficient_scope"` - indicating the specific type of authorization failure
>   - `scope="required_scope1 required_scope2"` - specifying the minimum scopes needed for the operation
>   - `resource_metadata` - the URI of the Protected Resource Metadata document
>   - `error_description` (optional) - human-readable description of the error

## Use Cases

### Use Case 1: MCP-Compliant Upstream (Scenario B)
Incremental consent with proper MCP scope challenges:
1. User authenticates with initial minimal scopes: `["files:read"]`
2. User attempts operation requiring additional scope
3. MCP upstream returns 403 with `WWW-Authenticate: Bearer error="insufficient_scope", scope="files:read files:write"`
4. Pomerium parses scope requirements from header
5. Pomerium initiates step-up OAuth with combined scopes
6. User grants additional permissions
7. Pomerium retries operation with new token

### Use Case 2: Legacy OAuth Provider (Scenario A)
Scope upgrade for traditional OAuth APIs:
1. User authenticates with initial scopes: `["https://www.googleapis.com/auth/drive.readonly"]`
2. User attempts operation that fails due to insufficient permissions
3. Upstream API returns error (403, or custom error format)
4. Pomerium detects scope insufficiency (via error parsing or configuration)
5. Pomerium re-initiates OAuth with additional scopes: `["drive.readonly", "drive.file"]`
6. User consents to new scopes
7. Pomerium retries operation with upgraded token

## Current State

### ✅ Implemented Features

#### As MCP Authorization Server (serving MCP clients):
- **OAuth 2.0 Authorization Server Metadata** ([handler_metadata.go](internal/mcp/handler_metadata.go))
  - Serves at: `/.well-known/oauth-authorization-server`
  - Registered in [controlplane/http.go](internal/controlplane/http.go) via `root.Path()`
  - Returns: issuer, endpoints (authorize, token, registration, revocation), PKCE support, scopes

- **Protected Resource Metadata** ([handler_metadata.go](internal/mcp/handler_metadata.go))
  - Serves at: `/.well-known/oauth-protected-resource/*` (PathPrefix)
  - Supports both root and path-specific discovery
  - Returns: resource identifier, authorization_servers, scopes_supported
  - Correctly extracts path using `strings.TrimPrefix(r.URL.Path, WellKnownProtectedResourceEndpoint)`

- **WWW-Authenticate Header Generation** ([handler_metadata.go](internal/mcp/handler_metadata.go))
  - Function: `Set401WWWAuthenticateHeader()`
  - Returns structured header using RFC 8941 Structured Field Values
  - Includes: `error="invalid_request"`, `error_description`, `resource_metadata` URL
  - **Missing**: Does not include `scope` parameter (should be added per MCP spec)

- **Client Registration**
  - Dynamic Client Registration endpoint exposed at `/mcp/register`
  - Authorization endpoint at `/mcp/authorize`
  - Token endpoint at `/mcp/token`
  - Revocation endpoint at `/mcp/revoke`

#### As Upstream OAuth Client (Scenario A - Legacy OAuth):
- **Manual Upstream OAuth Configuration** ([config/policy.go](config/policy.go), [host_info.go](internal/mcp/host_info.go))
  - Reads `upstream_oauth2` from policy MCP server config
  - Builds `oauth2.Config` with client_id, client_secret, endpoints, scopes
  - Stored per-host in `HostInfo.servers` map

- **OAuth Token Management** ([token.go](internal/mcp/token.go), [storage.go](internal/mcp/storage.go))
  - `GetUpstreamOAuth2Token()`: Retrieves and auto-refreshes tokens
  - Uses singleflight to prevent concurrent refresh requests
  - `StoreUpstreamOAuth2Token()`: Persists tokens to databroker
  - `DeleteUpstreamOAuth2Token()`: Removes tokens (disconnect flow)

- **OAuth Flow** ([handler_authorization.go](internal/mcp/handler_authorization.go), [handler_oauth_callback.go](internal/mcp/handler_oauth_callback.go))
  - Authorization endpoint checks if upstream OAuth required (`HasOAuth2ConfigForHost`)
  - If no token exists, redirects to upstream OAuth provider
  - Callback handler exchanges code for token and stores it
  - Connect endpoint (`/mcp/connect`) ensures user has upstream token before proceeding

- **Token Refresh**
  - Automatic via `oauth2.Config.TokenSource()` in `GetUpstreamOAuth2Token()`
  - Updates stored token if access_token or refresh_token changed
  - Preserves refresh_token if provider doesn't return new one

### ❌ Missing Features

#### Scope Challenge & Step-Up Authorization:
- **No 403 vs 401 distinction**: All auth failures treated similarly
- **No WWW-Authenticate parsing from upstreams**: Cannot detect scope challenges
- **No `insufficient_scope` error handling**: Cannot parse `error` parameter from upstream headers
- **No scope extraction**: Cannot parse `scope` parameter from upstream 403/401 responses
- **No scope merging logic**: Cannot combine existing + newly-required scopes
- **No step-up flow**: Cannot re-initiate OAuth with expanded scopes
- **No retry mechanism**: Cannot retry failed requests after scope upgrade

#### MCP Discovery as Client (Scenario B):
- **No upstream discovery**: Cannot fetch `/.well-known/oauth-protected-resource` from upstreams
- **No WWW-Authenticate parsing from 401**: Cannot extract `resource_metadata` URL from upstream
- **No fallback URI logic**: Cannot try path-specific → root discovery sequence
- **No AS metadata fetching**: Cannot discover upstream Authorization Servers
- **No multi-attempt AS discovery**: Cannot try OAuth 2.0 vs OIDC endpoints with path variations
- **No dynamic client registration to upstream AS**: Cannot register Pomerium as MCP client
- **No Client ID Metadata Document support**: Cannot use HTTPS URL as client_id for upstreams
- **No `discover_oauth` config option**: Must manually configure all OAuth details

#### Missing Configuration:
- **No `oauth_client_credentials`**: Cannot pre-configure Pomerium's credentials as MCP client
- **No `discover_oauth` flag**: Cannot enable automatic discovery mode
- **No scope mapping**: Cannot map provider-specific errors to scope requirements
- **No scope escalation rules**: Cannot define additional scopes to request on retry

### 🔧 Implementation Details

**Files involved:**
- `internal/mcp/handler_metadata.go` - Metadata serving (AS & PR)
- `internal/mcp/host_info.go` - Policy-to-OAuth config mapping
- `internal/mcp/token.go` - Token retrieval & refresh
- `internal/mcp/storage.go` - Token persistence
- `internal/mcp/handler_authorization.go` - Authorization flow orchestration
- `internal/mcp/handler_oauth_callback.go` - OAuth callback & token exchange
- `internal/mcp/handler_connect.go` - Connect flow for ensuring upstream tokens
- `internal/controlplane/http.go` - HTTP route registration
- `pkg/grpc/config/config.proto` - Configuration schema (UpstreamOAuth2)

**Data structures:**
- `AuthorizationServerMetadata` - RFC 8414 compliant
- `ProtectedResourceMetadata` - RFC 9728 compliant
- `HostInfo` - Maps hosts to OAuth configs
- `ServerHostInfo` - Per-server metadata (name, URL, OAuth config)
- `UpstreamOAuth2` (protobuf) - Configuration for legacy OAuth providers

## Implementation Tasks

### Phase 1: Core Scope Challenge Support
- [ ] Distinguish between 401 (authentication) and 403 (authorization) responses from upstreams
- [ ] Parse `WWW-Authenticate` headers from upstream 403 responses
- [ ] Extract `error="insufficient_scope"` and `scope` parameters
- [ ] Implement step-up authorization flow (re-initiate OAuth with additional scopes)
- [ ] Handle scope merging (preserve existing + add new required scopes)
- [ ] Add retry logic after scope upgrade (with reasonable limits)

### Phase 2: MCP Discovery Support (Scenario B)

#### As MCP Client (consuming upstream MCP servers):

**Protected Resource Metadata Discovery** (per MCP spec requirements):
- [ ] Parse `WWW-Authenticate` headers from upstream 401 responses
- [ ] Extract `resource_metadata` URL from header when present
- [ ] Implement fallback well-known URI discovery with proper priority:
  1. [ ] If `resource_metadata` in header: use that URL directly
  2. [ ] Try path-specific: `https://upstream/.well-known/oauth-protected-resource{upstream_mcp_path}`
     - Example: If MCP endpoint is `/api/mcp`, try `/.well-known/oauth-protected-resource/api/mcp`
  3. [ ] Fall back to root: `https://upstream/.well-known/oauth-protected-resource`
- [ ] Fetch and parse Protected Resource Metadata documents from upstream
- [ ] Extract `authorization_servers` array from metadata
- [ ] Extract `scopes_supported` for scope selection

**Authorization Server Metadata Discovery** (multi-attempt per MCP spec):
- [ ] For issuer URLs **with** path components (e.g., `https://auth.example.com/tenant1`), try in order:
  1. OAuth 2.0 with path insertion: `/.well-known/oauth-authorization-server/tenant1`
  2. OIDC with path insertion: `/.well-known/openid-configuration/tenant1`
  3. OIDC with path appending: `/tenant1/.well-known/openid-configuration`
- [ ] For issuer URLs **without** path components (e.g., `https://auth.example.com`), try:
  1. OAuth 2.0: `/.well-known/oauth-authorization-server`
  2. OIDC: `/.well-known/openid-configuration`
- [ ] Parse AS metadata and extract endpoints (authorize, token, registration, etc.)
- [ ] Check for `code_challenge_methods_supported` (PKCE requirement)

**Client Registration**:
- [ ] Support Dynamic Client Registration when `registration_endpoint` available
- [ ] Support Client ID Metadata Documents when `client_id_metadata_document_supported: true`
- [ ] Fall back to pre-configured client credentials (`oauth_client_credentials`)
- [ ] Add config option: `discover_oauth: true`

#### As MCP Server (serving MCP clients):
- [ ] Verify `PathPrefix` handler correctly extracts path from all variants:
  - `/.well-known/oauth-protected-resource` (root)
  - `/.well-known/oauth-protected-resource/api/mcp` (path-specific)
- [ ] Test discovery from clients using both methods (WWW-Authenticate + well-known URIs)
- [ ] Ensure `resource` field in metadata correctly reflects the requested path

### Phase 3: Legacy OAuth Enhancements (Scenario A)
- [ ] Keep existing `upstream_oauth2` configuration support
- [ ] Add scope-to-error mapping for common OAuth providers
- [ ] Detect scope insufficiency from provider-specific error responses
- [ ] Support incremental scope requests for legacy providers

### Phase 4: Pomerium as MCP Client Bridge
- [ ] When upstream is MCP-compliant, register Pomerium as MCP client
- [ ] Implement proper token audience validation (RFC 8707)
- [ ] Handle token refresh for upstream tokens
- [ ] Add configuration for Pomerium's MCP client credentials
- [ ] Document Pomerium's dual role (AS for clients, client for upstreams)

### Phase 5: Configuration & Documentation
- [ ] Add scope configuration schema for both scenarios
- [ ] Document when to use `upstream_oauth2` vs `discover_oauth`
- [ ] Provide examples for common providers (Google, GitHub, etc.)
- [ ] Document discovery flow corner cases (path-specific vs root)
- [ ] Add troubleshooting guide for OAuth flows

## Example Responses

### Example 1: MCP-Compliant Upstream 403 Response
```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
                         scope="files:read files:write user:profile",
                         resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         error_description="Additional file write permission required"
```

### Example 2: MCP-Compliant Upstream 401 Response (Initial Discovery)
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/api/v1",
                         scope="files:read",
                         error="invalid_token",
                         error_description="No access token was provided"
```

### Example 3: Legacy Provider Error (Google Drive API)
```json
{
  "error": {
    "code": 403,
    "message": "Insufficient Permission: Request had insufficient authentication scopes.",
    "errors": [{
      "domain": "global",
      "reason": "insufficientPermissions",
      "message": "Insufficient Permission"
    }]
  }
}
```
Pomerium would need to detect this and map it to scope upgrade.

## Scope Selection Strategy

### For MCP-Compliant Upstreams (Scenario B)
From the MCP specification, Pomerium acting as MCP client **MUST** follow this priority:

1. **Use `scope` parameter** from the `WWW-Authenticate` header (401 or 403), if provided
2. **If `scope` is not available**, use all scopes defined in `scopes_supported` from the Protected Resource Metadata document
3. **For step-up auth**, merge existing granted scopes + new required scopes

### For Legacy OAuth Providers (Scenario A)
Pomerium **MUST** rely on pre-configured scopes in `upstream_oauth2.scopes`:

1. **Initial auth**: Use scopes from configuration
2. **Step-up auth**: Merge configured scopes + additional scopes from:
   - Error response parsing (provider-specific)
   - Scope mapping configuration
   - Admin-defined scope escalation rules

## Discovery Flow Corner Cases

### Case 1: Path-Specific MCP Endpoint
```
Upstream MCP endpoint: https://api.example.com/v1/mcp
Discovery attempts:
1. Check WWW-Authenticate header from 401 for resource_metadata
2. If not present, try: https://api.example.com/.well-known/oauth-protected-resource/v1/mcp
3. Fall back to: https://api.example.com/.well-known/oauth-protected-resource
```

### Case 2: Root MCP Endpoint
```
Upstream MCP endpoint: https://mcp.example.com
Discovery attempts:
1. Check WWW-Authenticate header from 401 for resource_metadata
2. If not present, try: https://mcp.example.com/.well-known/oauth-protected-resource
```

### Case 3: Authorization Server with Path Component
```
Discovered AS issuer: https://auth.example.com/tenant1
AS metadata discovery attempts:
1. https://auth.example.com/.well-known/oauth-authorization-server/tenant1
2. https://auth.example.com/.well-known/openid-configuration/tenant1
3. https://auth.example.com/tenant1/.well-known/openid-configuration
```

## Acceptance Criteria

### For MCP-Compliant Upstreams (Scenario B)
1. ✅ Pomerium attempts to parse `WWW-Authenticate` from upstream 401 responses
2. ✅ Pomerium extracts `resource_metadata` URL when present
3. ✅ Pomerium falls back to well-known URI probing (path-specific → root)
4. ✅ Pomerium fetches and parses Protected Resource Metadata
5. ✅ Pomerium discovers Authorization Server with multi-attempt logic
6. ✅ Pomerium registers as MCP client (dynamic reg or client ID metadata doc)
7. ✅ Pomerium parses 403 responses with `insufficient_scope` from upstreams
8. ✅ Pomerium extracts required scopes from `WWW-Authenticate` header
9. ✅ Step-up authorization flow works end-to-end for MCP upstreams
10. ✅ Retry after scope upgrade succeeds

### For Legacy OAuth Providers (Scenario A)
1. ✅ `upstream_oauth2` configuration continues to work
2. ✅ Pomerium detects scope insufficiency from provider-specific errors
3. ✅ Pomerium re-initiates OAuth with additional scopes
4. ✅ Common providers (Google, GitHub) are supported with examples
5. ✅ Retry after scope upgrade succeeds

### General
1. ✅ 401 (authentication) and 403 (authorization) are properly distinguished
2. ✅ Token refresh works for both scenarios
3. ✅ Configuration examples cover both scenarios
4. ✅ Documentation explains discovery corner cases
5. ✅ Documentation explains when to use each approach

## Configuration Examples

### Example 1: MCP-Compliant Upstream with Discovery
```yaml
routes:
  - from: https://mcp-client.example.com
    to: https://upstream-mcp.example.com/api/v1
    policy:
      - allow:
          and:
            - user:
                is: user@example.com
    mcp:
      server:
        path: /mcp
        discover_oauth: true
        # Optional: If AS doesn't support dynamic registration
        oauth_client_credentials:
          client_id: pomerium-mcp-client
          client_secret: ${MCP_CLIENT_SECRET}
```
Discovery will try:
1. `WWW-Authenticate` header from 401
2. `https://upstream-mcp.example.com/.well-known/oauth-protected-resource/api/v1/mcp`
3. `https://upstream-mcp.example.com/.well-known/oauth-protected-resource`

### Example 2: Legacy Google Drive API
```yaml
routes:
  - from: https://drive-tool.example.com
    to: https://tool-backend.internal
    policy:
      - allow:
          and:
            - user:
                is: user@example.com
    mcp:
      server:
        upstream_oauth2:
          client_id: ${GOOGLE_CLIENT_ID}
          client_secret: ${GOOGLE_CLIENT_SECRET}
          oauth2_endpoint:
            auth_url: https://accounts.google.com/o/oauth2/v2/auth
            token_url: https://oauth2.googleapis.com/token
          scopes:
            - https://www.googleapis.com/auth/drive.readonly
            # Additional scopes for step-up auth:
            - https://www.googleapis.com/auth/drive.file
```

### Example 3: Hybrid Approach (Try Discovery, Fall Back to Manual)
```yaml
routes:
  - from: https://mcp.example.com
    to: https://upstream.example.com
    mcp:
      server:
        discover_oauth: true  # Try MCP discovery first
        upstream_oauth2:      # Fall back to manual config if discovery fails
          client_id: ${OAUTH_CLIENT_ID}
          client_secret: ${OAUTH_CLIENT_SECRET}
          oauth2_endpoint:
            auth_url: https://auth.example.com/authorize
            token_url: https://auth.example.com/token
          scopes: ["read", "write"]
```

## References

- [RFC 6750 Section 3.1](/.docs/RFC/rfc6750.txt)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [MCP Authorization - Scope Challenge Handling](/.docs/mcp/basic/authorization.mdx)
- [MCP Authorization - Protected Resource Metadata Discovery](/.docs/mcp/basic/authorization.mdx#protected-resource-metadata-discovery-requirements)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-07: Updated to reflect dual-scenario architecture (MCP-compliant vs legacy OAuth providers)
- 2026-01-07: Added comprehensive discovery flow corner cases and multi-attempt logic per MCP spec
