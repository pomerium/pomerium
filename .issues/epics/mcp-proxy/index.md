---
id: mcp-proxy-authorization-bridge
title: "MCP Proxy: Authorization Bridge for Remote MCP Servers"
status: planning
created: 2026-01-19
updated: 2026-02-02
priority: high
owner: ""
labels:
  - mcp
  - oauth2
  - proxy
  - authorization
  - architecture
---

# Epic: MCP Proxy Authorization Bridge for Remote MCP Servers

## Overview

This epic tracks the design and implementation of Pomerium acting as an authorization bridge between external MCP clients and remote MCP servers that require their own OAuth 2.1 authorization flows. Pomerium would function as both an MCP Server (to external clients) and an MCP Client (to upstream remote MCP servers), handling the complex authorization choreography transparently.

### Design Principles

1. **Protocol-First**: Leverage MCP's built-in discovery mechanisms (RFC 9728, RFC 8414) rather than duplicating configuration
2. **Zero Configuration**: Only configure the route itself - all OAuth client details are automatically derived
3. **Standards Compliance**: Follow OAuth 2.1 and MCP specifications exactly as written
4. **Zero-Knowledge Discovery**: Pomerium should work with any compliant MCP server without prior knowledge of its authorization server
5. **Implementation Hiding**: OAuth client registration details (CIMD, redirect URIs, etc.) are implementation details, not user configuration

## Problem Statement

Currently, Pomerium acts as an MCP authorization server and gateway, allowing MCP clients to authenticate via OAuth 2.1 and access MCP servers behind Pomerium. However, the upstream MCP servers are assumed to be internal services that trust Pomerium's authorization decisions.

A growing use case involves proxying to **remote MCP servers** (e.g., third-party SaaS providers, partner services, or federated MCP endpoints) that:

1. Have their own authorization servers
2. Require OAuth 2.1 token acquisition before accepting requests
3. May use different scopes, audiences, and token formats
4. May require user consent for specific permissions

Without a bridge, MCP clients would need to independently manage authorization flows for each remote server, leading to:
- Poor user experience (multiple consent flows)
- Complex client implementations
- Inconsistent security policies
- No centralized audit or policy enforcement

## Proposed Architecture

### Dual-Role Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Pomerium MCP Proxy                             │
│                                                                             │
│  ┌─────────────────────────┐      ┌─────────────────────────────────────┐  │
│  │   MCP Server Role       │      │       MCP Client Role               │  │
│  │                         │      │                                     │  │
│  │  - Accepts MCP requests │      │  - Connects to remote MCP servers   │  │
│  │  - OAuth 2.1 AS for     │      │  - Handles OAuth 2.1 flows with     │  │
│  │    external clients     │      │    remote authorization servers     │  │
│  │  - Session management   │      │  - Token caching and refresh        │  │
│  │  - Policy enforcement   │      │  - Credential management            │  │
│  └────────────┬────────────┘      └─────────────────┬───────────────────┘  │
│               │                                     │                       │
└───────────────┼─────────────────────────────────────┼───────────────────────┘
                │                                     │
                ▼                                     ▼
        ┌───────────────┐                   ┌────────────────────┐
        │  MCP Clients  │                   │  Remote MCP        │
        │  (Claude,     │                   │  Servers           │
        │   IDE plugins,│                   │  + Their OAuth AS  │
        │   etc.)       │                   │                    │
        └───────────────┘                   └────────────────────┘
```

### Authorization Flow

> **Architecture**: Pomerium uses ext_authz for request-path authorization and ext_proc for response-path interception. Discovery is **reactive**: triggered by 401 `WWW-Authenticate` responses from upstream, exactly as the MCP spec describes. See [upstream-discovery.md](./upstream-discovery.md) for details.

```
┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────────┐    ┌────────────────┐
│MCP Client│    │  ext_authz   │    │   ext_proc   │    │ Remote MCP     │    │ Remote OAuth   │
│          │    │  (request)   │    │  (response)  │    │ Server         │    │ Auth Server    │
└────┬─────┘    └──────┬───────┘    └──────┬───────┘    └───────┬────────┘    └───────┬────────┘
     │                 │                   │                    │                     │
     │ 1. MCP request  │                   │                    │                     │
     │ (with Pomerium  │                   │                    │                     │
     │  access token)  │                   │                    │                     │
     │────────────────>│                   │                    │                     │
     │                 │                   │                    │                     │
     │                 │ 2. No upstream    │                    │                     │
     │                 │    token cached   │                    │                     │
     │                 │    → forward as-is│                    │                     │
     │                 │───────────────────────────────────────>│                     │
     │                 │                   │                    │                     │
     │                 │                   │ 3. 401 Unauthorized│                     │
     │                 │                   │    WWW-Authenticate: Bearer              │
     │                 │                   │      resource_metadata="..."             │
     │                 │                   │<───────────────────│                     │
     │                 │                   │                    │                     │
     │                 │                   │ 4. REACTIVE DISCOVERY                    │
     │                 │                   │    Parse WWW-Authenticate                │
     │                 │                   │    Fetch Protected Resource Metadata     │
     │                 │                   │───────────────────>│                     │
     │                 │                   │<───────────────────│                     │
     │                 │                   │    Fetch AS Metadata (RFC 8414)          │
     │                 │                   │────────────────────────────────────────>│
     │                 │                   │<────────────────────────────────────────│
     │                 │                   │    Cache discovery results               │
     │                 │                   │                    │                     │
     │ 5. ImmediateResponse: 401            │                    │                     │
     │    WWW-Authenticate: Bearer         │                    │                     │
     │      resource_metadata="..."        │                    │                     │
     │    (points to Pomerium's PRM)       │                    │                     │
     │<────────────────────────────────────│                    │                     │
     │                 │                   │                    │                     │
     │ 6. MCP client   │                   │                    │                     │
     │    re-runs MCP  │                   │                    │                     │
     │    OAuth flow   │                   │                    │                     │
     │    with Pomerium│                   │                    │                     │
     │────────────────>│                   │                    │                     │
     │                 │                   │                    │                     │
     │                 │ 7. Authorize endpoint finds pending    │                     │
     │                 │    upstream auth → redirects browser   │                     │
     │                 │    to upstream AS authorize endpoint   │                     │
     │<────────────────│                   │                    │                     │
     │                 │                   │                    │                     │
     │ 8. Browser:     │                   │                    │ 8a. Fetch CIMD      │
     │    user consent │                   │                    │  (auto-generated)   │
     │─────────────────────────────────────────────────────────────────────────────>│
     │                 │                   │                    │                     │
     │                 │                   │                    │ 9. Auth Code        │
     │<──────────────────────────────────────────────────────────────────────────────│
     │                 │                   │                    │                     │
     │                 │ 10. ClientOAuthCallback: code→token exchange                │
     │────────────────>│──────────────────────────────────────────────────────────────>│
     │                 │<──────────────────────────────────────────────────────────────│
     │                 │ 11. Cache token   │                    │                     │
     │                 │    + complete MCP │                    │                     │
     │                 │    auth flow via  │                    │                     │
     │                 │    AuthorizationResponse               │                     │
     │                 │                   │                    │                     │
     │ 12. MCP client  │                   │                    │                     │
     │    gets new     │                   │                    │                     │
     │    Pomerium     │                   │                    │                     │
     │    token,retries│                   │                    │                     │
     │────────────────>│                   │                    │                     │
     │                 │                   │                    │                     │
     │                 │ 14. Token cached, │                    │                     │
     │                 │     inject        │                    │                     │
     │                 │     Authorization │                    │                     │
     │                 │───────────────────────────────────────>│                     │
     │                 │                   │                    │                     │
     │                 │                   │ 15. 200 OK         │                     │
     │                 │                   │ (pass through)     │                     │
     │ 16. MCP response│                   │                    │                     │
     │<────────────────────────────────────│<───────────────────│                     │
     │                 │                   │                    │                     │
```

## Key Components

### 1. Remote MCP Server Registry & Automatic Client Registration

Configuration for upstream MCP servers that require authorization is **zero configuration**. Pomerium automatically generates and hosts a Client ID Metadata Document for each MCP proxy route.

#### Route Configuration

Simply configure the route - everything else is automatic:

```yaml
routes:
  - from: https://mcp.example.com
    to: https://remote-mcp.provider.com
    mcp:
      server: {}  # Empty server block enables auto-discovery proxy mode
      # That's it! No client credentials, no authorization server config needed
      # Tokens are automatically bound to the authenticated user
```

#### Automatic Client ID Metadata Document

Pomerium automatically generates and hosts a CIMD for this route at:
```
https://mcp.example.com/.well-known/mcp-client-metadata.json
```

The document content is automatically derived from the route configuration:

```json
{
  "client_id": "https://mcp.example.com/.well-known/mcp-client-metadata.json",
  "client_name": "Pomerium MCP Proxy - mcp.example.com",
  "client_uri": "https://mcp.example.com",
  "redirect_uris": [
    "https://mcp.example.com/.pomerium/oauth/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

**All fields derived automatically:**
- `client_id`: The CIMD URL itself (based on route's `from:` URL)
- `client_name`: Generated from route hostname
- `client_uri`: Same as route's `from:` URL
- `redirect_uris`: Derived from route's `from:` URL + standard callback path
- Standard OAuth 2.1 grant types and response types

#### How It Works

When Pomerium needs to connect to a remote MCP server as a client:

1. **Route receives request** → Pomerium needs to proxy to upstream
2. **Discovers upstream AS** → Via RFC 9728 discovery
3. **Checks AS capabilities** → Looks for `client_id_metadata_document_supported: true`
4. **Presents CIMD URL** → Uses `https://mcp.example.com/.well-known/mcp-client-metadata.json` as `client_id`
5. **Remote AS fetches CIMD** → Validates client metadata and redirect URIs
6. **Authorization proceeds** → Standard OAuth 2.1 flow
7. **Token cached per route** → Isolated to this specific route/upstream combination

#### Per-Route Client Identity

Each route acts as a separate OAuth client to remote servers, providing:

- **Token Isolation**: Tokens acquired via one route don't leak to other routes
- **Separate Consent**: Users can grant different permissions per route
- **Independent Lifecycle**: Each route's tokens managed independently
- **Clear Attribution**: Remote servers see which Pomerium route is accessing them

#### No Fallback to Pre-Registration

For remote MCP servers that don't support Client ID Metadata Documents, we would not fall back to dynamic client registration, as it has been deprecated.

#### What Gets Handled Automatically

- ✅ **Client ID generation** - Derived from route URL
- ✅ **Client metadata document** - Auto-generated and hosted
- ✅ **Redirect URI configuration** - Standard callback path per route
- ✅ **Authorization server discovery** - Via RFC 9728 Protected Resource Metadata
- ✅ **Authorization server capabilities** - Via RFC 8414 AS metadata discovery
- ✅ **Supported scopes** - Via `scopes_supported` in Protected Resource Metadata
- ✅ **PKCE support detection** - From AS metadata

#### Why This Approach?

1. **Zero Configuration Surface**: No new config options - just configure routes
2. **No Manual Registration**: No pre-registration with remote authorization servers needed
3. **Implementation Detail**: OAuth client mechanics are hidden from operators
4. **Standards Compliant**: Uses CIMD exactly as MCP spec intends
5. **Secure by Default**: Per-route isolation prevents token leakage
6. **Scalable**: Add 100 remote MCP servers = 100 route definitions, nothing more

### 2. Upstream Token Manager

Responsible for:
- **Token Acquisition**: Executing OAuth 2.1 flows against remote authorization servers
- **Token Caching**: Storing tokens per-user/per-upstream with appropriate TTLs
- **Token Refresh**: Proactively refreshing tokens before expiration
- **Token Revocation**: Cleaning up tokens on session termination
- **Credential Storage**: Secure storage of client credentials for each upstream

### 3. Authorization Choreographer

Handles the multi-step authorization flow:
- Detects when upstream authorization is needed (401 from upstream, missing cached token)
- Initiates OAuth 2.1 flow with remote AS (using PKCE, PAR if supported)
- Manages user consent if remote AS requires it
- Coordinates between client-facing session and upstream tokens

### 4. Request Transformer

Transforms requests between the client-facing MCP session and upstream:
- Replaces Pomerium-issued tokens with upstream-specific tokens
- Maps session identifiers appropriately
- Handles header transformations (MCP-Session-Id, etc.)
- May need to handle protocol version differences

### 5. Upstream Discovery

**Reactive discovery** of remote MCP server authorization requirements, triggered by 401 responses from upstream via ext_proc. Follows the MCP specification (RFC 9728) exactly.

#### Discovery Flow

When Pomerium (acting as MCP client) proxies to a remote MCP server:

1. **Forward Request**: ext_authz forwards request to upstream (with cached token if available, otherwise as-is)
2. **Upstream 401**: ext_proc intercepts the `WWW-Authenticate` response
3. **Parse Discovery Hints**: Extract `resource_metadata` URL and `scope` parameter
4. **Fetch Protected Resource Metadata**: From `resource_metadata` URL (preferred) or well-known endpoints (fallback)
5. **Extract Authorization Server(s)**: Parse `authorization_servers` array from metadata
6. **Discover AS Capabilities**: Fetch AS metadata (RFC 8414)
7. **Redirect for OAuth**: Return `ImmediateResponse` redirect to authorization endpoint
8. **Cache Discovery Results**: Store for ext_authz short-circuit optimization

#### ext_authz Short-Circuit Optimization

After the first reactive discovery, ext_authz can redirect tokenless users immediately without the round-trip to upstream. This optimization means only the very first user hits the full 401→discover→redirect cycle.

#### Discovery Caching

- Discovery results cached per upstream server URL
- Respect HTTP cache headers, max TTL of 1 hour
- Concurrent discovery requests coalesced via `singleflight.Group`
- Invalidate on repeated authorization failures

#### Zero Configuration Required

The entire authorization flow is automatic:
- Authorization server discovery via RFC 9728 (reactive, from 401 WWW-Authenticate)
- Authorization server capability negotiation via RFC 8414
- Client registration via auto-generated Client ID Metadata Documents
- Token acquisition, caching, and refresh

Administrators configure **only** the route (`from:` and `to:` URLs). Everything else is derived or discovered automatically.

## Security Considerations

### Token Isolation

- Upstream tokens MUST be bound to the authenticated user
- Tokens MUST NOT be shared across users
- Tokens are cached per-user, per-route, per-upstream for proper isolation

### Confused Deputy Protection

- Pomerium MUST validate that the user has permission to access the upstream resource
- Resource indicators (RFC 8707) MUST be used when acquiring upstream tokens
- Token audience MUST match the upstream server

### Credential Security

- Client secrets for upstream servers MUST be stored securely
- Support for external secret stores (Vault, cloud KMS)
- Rotation support for upstream client credentials
- No logging of tokens or credentials

### Consent Transparency

- Users MUST be informed when consent is being requested on their behalf
- Pomerium SHOULD provide visibility into what permissions are being delegated
- Option to require explicit user approval before acquiring upstream tokens

### Token Lifecycle

- Clear policies for token revocation when:
  - User session ends
  - Upstream access is revoked in policy
  - User explicitly revokes access
- Audit logging of all token acquisition and usage

## Token Binding

Upstream tokens are always bound to the authenticated user: `(user_id, route_id, upstream_server)`.

This ensures:
- Tokens are never shared across users
- Each user maintains their own consent/authorization with the upstream
- Token revocation is scoped to individual users
- Tokens are shared across all sessions for the same user

## Open Questions

1. **Response Interception**: Envoy ext_authz cannot intercept responses. How should we implement full response interception to support reactive discovery (401 handling) and step-up authorization (403 insufficient_scope)?

 > **DECIDED & IMPLEMENTED**: Using Envoy's **ext_proc** filter for response interception. Scaffolding merged (commit 968b0a36f). Discovery is now **reactive** — triggered by 401 `WWW-Authenticate` from upstream via ext_proc. See [upstream-discovery.md](./upstream-discovery.md) and [response-interception-implementation.md](./response-interception-implementation.md).

2. **CIMD Trust Policies**: Should Pomerium validate remote authorization servers before presenting its CIMD? (e.g., domain allowlists, certificate validation, reputation checks)

 > out of scope for now

3. **User Consent UX**: How should consent be presented when Pomerium needs to acquire tokens on behalf of the user? Redirect flow? Embedded consent? Pre-authorization?

> Redirect flow.

4. **Token Storage Backend**: Should upstream tokens use the existing session storage, or a dedicated token store with different lifecycle management?

> existing databroker storage, just with some dedicated record type.

5. **Multi-Hop Scenarios**: What if a remote MCP server itself proxies to other services? How deep should the authorization chain go?

> that is theoretically possible, but it would likely be opaque for us, so we should just support it transparently.

6. **Scope Mapping**: Should there be a mapping layer between scopes requested by MCP clients and scopes requested from upstream servers?

> Pomerium itself does not manage any scopes, so the scopes would be passthru from the upstream.

7. **Error Propagation**: How should authorization failures from upstream be communicated to clients? Transparent passthrough or abstracted errors?

> transparent passtrhough

8. **Rate Limiting**: Should Pomerium enforce rate limits on upstream token acquisition to prevent abuse?

> out of scope for now

9. **Offline Access**: Should Pomerium request refresh tokens from upstream servers? What are the security implications?

> yes. mcp assumes short lived access tokens and long lived refresh tokens.

## Dependencies

### Required for Core Functionality

- [MCP OAuth 2.1 Authorization Server](../mcp/index.md) - Core MCP AS implementation
- [Client ID Metadata Documents](../mcp/client-id-metadata-documents.md) - **Critical**: Enables zero-configuration client registration with remote servers
- [Resource Indicator Support](../mcp/resource-indicator-support.md) - Required for proper token binding
- [Token Audience Validation](../mcp/token-audience-validation.md) - Required for security
- [Refresh Token Support](../mcp/mcp-refresh-token-and-session-lifecycle.md) - For upstream token refresh

## Issues

**Task Execution Guide**: See [TASK_EXECUTION_ORDER.md](./TASK_EXECUTION_ORDER.md) for dependency graph and recommended implementation sequence.

### Implementation Status Summary

| Phase | Progress | Key Blocker |
|-------|----------|-------------|
| Phase 1: Foundation | 2/3 | Route config schema ✅ + CIMD hosting ✅ implemented; token storage pending |
| Phase 2: Discovery | ✅ 1/1 | Reactive discovery via ext_proc implemented |
| Phase 3: Authorization | ✅ 2/2 | Choreographer + OAuth client flow implemented |
| Phase 4: Token Management | 0/1 | Existing patterns available |
| Phase 5: Request Pipeline | 1/2 | Token injection via ext_proc ✅; error propagation pending |
| Phase 6: Security | 0/2 | Critical - parallel with other work |
| Phase 7: Quality | 0/2 | After implementation |
| Phase 8: Response Interception | ✅ 3/3 | ext_proc 401/403 handling, WWW-Authenticate parsing, and programmatic client flow all implemented |

### Phase 1: Foundation

| Issue | Title | Status | Priority | Description |
|-------|-------|--------|----------|-------------|
| [route-configuration-schema](./route-configuration-schema.md) | Route Configuration Schema | **implemented** | high | ✅ Schema supports auto-discovery via nil `upstream_oauth2` ([host_info.go:122](internal/mcp/host_info.go#L122)) |
| [per-route-cimd-hosting](./per-route-cimd-hosting.md) | Per-Route CIMD Hosting | **implemented** | high | ✅ Auto-generates Client ID Metadata Documents per route ([handler_cimd.go](internal/mcp/handler_cimd.go)) |
| [upstream-token-storage](./upstream-token-storage.md) | Upstream Token Storage | open | high | Databroker record type for upstream tokens (existing patterns in [storage.go](internal/mcp/storage.go)) |

### Phase 2: Discovery

| Issue | Title | Status | Priority | Description |
|-------|-------|--------|----------|-------------|
| [upstream-discovery](./upstream-discovery.md) | Upstream Discovery | **implemented** | high | ✅ Reactive RFC 9728 + RFC 8414 discovery via ext_proc 401 interception (`runDiscovery` in upstream_auth.go) |

### Phase 3: Authorization Flow

| Issue | Title | Status | Priority | Description |
|-------|-------|--------|----------|-------------|
| [authorization-choreographer](./authorization-choreographer.md) | Authorization Choreographer | **implemented** | high | ✅ ext_proc returns 401 → MCP client re-auths → Authorize endpoint redirects browser to upstream AS → callback completes flow |
| [upstream-oauth-client-flow](./upstream-oauth-client-flow.md) | OAuth 2.1 Client Flow | **implemented** | high | ✅ PKCE authorization code flow as client (`handle401` + `ClientOAuthCallback` + token exchange) |

### Phase 4: Token Management

| Issue | Title | Status | Priority | Description |
|-------|-------|--------|----------|-------------|
| [upstream-token-lifecycle](./upstream-token-lifecycle.md) | Token Lifecycle Management | open | high | Caching, refresh, and revocation (patterns in [token.go](internal/mcp/token.go)) |

### Phase 5: Request Pipeline

| Issue | Title | Status | Priority | Description |
|-------|-------|--------|----------|-------------|
| [request-transformation](./request-transformation.md) | Request Transformation | **implemented** | high | ✅ Token injection via ext_proc `handleRequestHeaders` + `injectAuthorizationHeader` |
| [upstream-error-propagation](./upstream-error-propagation.md) | Error Propagation | open | medium | Pass through upstream errors |

### Phase 6: Security

| Issue | Title | Status | Priority | Description |
|-------|-------|--------|----------|-------------|
| [token-isolation-enforcement](./token-isolation-enforcement.md) | Token Isolation | open | **critical** | Per-user token isolation enforcement |
| [upstream-resource-indicators](./upstream-resource-indicators.md) | Resource Indicators | open | high | RFC 8707 for upstream tokens (MCP spec MUST) |

### Phase 7: Quality & Documentation

| Issue | Title | Status | Priority | Description |
|-------|-------|--------|----------|-------------|
| [e2e-proxy-conformance-tests](./e2e-proxy-conformance-tests.md) | E2E Conformance Tests | open | high | End-to-end test coverage |
| [proxy-operator-documentation](./proxy-operator-documentation.md) | Operator Documentation | open | medium | Documentation for operators |

### Phase 8: Response Interception (ext_proc)

| Issue | Title | Status | Priority | Description |
|-------|-------|--------|----------|-------------|
| [response-interception-implementation](./response-interception-implementation.md) | ext_proc Response Interception | **implemented** | high | ✅ 401/403 handling returns 401 to trigger MCP client re-auth; Authorize endpoint + ClientOAuthCallback complete flow |
| [www-authenticate-parser](./www-authenticate-parser.md) | WWW-Authenticate Parser | **implemented** | high | ✅ `ParseWWWAuthenticate` in www_authenticate.go parses Bearer challenge headers |
| [step-up-authorization](./step-up-authorization.md) | Step-Up Authorization Flow | **implemented** | medium | ✅ 403 insufficient_scope handled via same `handle401` path with expanded scopes |

### Normative Documentation

All task files cross-reference the following normative documents:

| Document | Path | Key Sections Used |
|----------|------|-------------------|
| MCP Authorization Spec | [/.docs/mcp/basic/authorization.mdx](/.docs/mcp/basic/authorization.mdx) | Discovery, CIMD, PKCE, Resource Indicators, Scope Selection |
| MCP Security Best Practices | [/.docs/mcp/basic/security_best_practices.mdx](/.docs/mcp/basic/security_best_practices.mdx) | Token passthrough, confused deputy |
| OAuth 2.1 Draft | [/.docs/RFC/draft-ietf-oauth-v2-1.txt](/.docs/RFC/draft-ietf-oauth-v2-1.txt) | PKCE, state, token handling |
| RFC 9728 | [/.docs/RFC/rfc9728.txt](/.docs/RFC/rfc9728.txt) | Protected Resource Metadata |
| RFC 8414 | [/.docs/RFC/rfc8414.txt](/.docs/RFC/rfc8414.txt) | Authorization Server Metadata |
| RFC 8707 | [/.docs/RFC/rfc8707.txt](/.docs/RFC/rfc8707.txt) | Resource Indicators |
| OAuth CIMD Draft | [/.docs/RFC/draft-ietf-oauth-client-id-metadata-document.txt](/.docs/RFC/draft-ietf-oauth-client-id-metadata-document.txt) | Client ID Metadata Documents |

## Success Criteria

1. **Truly Zero Configuration**: Adding a remote MCP server proxy requires only configuring `from:` and `to:` URLs - no OAuth configuration, no client credentials, no authorization server URLs
2. **Automatic CIMD Generation**: Pomerium automatically generates and hosts a Client ID Metadata Document for each proxy route at `{route}/.well-known/mcp-client-metadata.json`
3. **Auto-Discovery**: Pomerium automatically discovers authorization requirements for any RFC 9728-compliant MCP server without explicit configuration
4. **Proxying**: Pomerium can proxy to remote MCP servers requiring OAuth 2.1 authorization
5. **Single Sign-On**: Users authenticate once with Pomerium; upstream authorization is handled transparently
6. **Per-Route Isolation**: Tokens and client identities are isolated per route, preventing cross-route token leakage
7. **Lifecycle Management**: Token lifecycle (acquisition, refresh, revocation) is fully managed automatically
8. **Audit Trail**: Complete audit trail for all upstream token operations
9. **Security Review**: Passes security review for confused deputy and token leakage scenarios
10. **Documentation**: Clear documentation for configuring remote MCP server proxying

## References

- [MCP Specification](./docs/mcp)
- [OAuth 2.1 Draft](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [RFC 8707 - Resource Indicators for OAuth 2.0](/.docs/RFC/rfc8707.txt)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](/.docs/RFC/rfc9728.txt)
- [RFC 9126 - Pushed Authorization Requests](/.docs/RFC/rfc9126.txt)

## Log

- 2026-02-05: **MAJOR**: Upstream discovery rewritten for reactive model — triggered by 401 WWW-Authenticate via ext_proc instead of proactive well-known probing; added ext_authz cached-discovery short-circuit optimization; step-up auth (403 insufficient_scope) now supported
- 2026-02-05: ext_proc scaffolding merged (commit 968b0a36f) - response interception now IN SCOPE; reclassified from "future" to Phase 8; added www-authenticate-parser and step-up-authorization sub-tasks
- 2026-02-04: Removed UpstreamTokenBinding configuration; tokens are always bound to user
- 2026-02-02: Added future-response-interception task documenting ext_proc requirements for reactive discovery and step-up auth
- 2026-02-02: **MAJOR**: Updated Authorization Flow to proactive discovery model via `initialize` interception (ext_authz cannot intercept responses); documented architectural constraint
- 2026-02-02: Updated all task files with concrete implementation reasoning and cross-references to normative docs; marked per-route-cimd-hosting as implemented; added implementation status summary to index
- 2026-01-26: Simplified token binding to user-only (removed per_session option)
- 2026-01-26: Broke down epic into 12 individual task files organized into 7 implementation phases
- 2026-01-26: Updated to automatically generate and host per-route Client ID Metadata Documents; eliminated all OAuth configuration requirements - only route URLs needed; CIMD and redirect URIs derived automatically from route configuration
- 2026-01-19: Epic created with high-level architecture design
