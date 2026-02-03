---
id: per-route-cimd-hosting
title: "Auto-Generated Per-Route Client ID Metadata Documents"
status: implemented
created: 2026-01-26
updated: 2026-02-02
priority: high
labels:
  - mcp
  - proxy
  - oauth2
  - cimd
deps:
  - route-configuration-schema
---

# Auto-Generated Per-Route Client ID Metadata Documents

## Summary

Implement automatic generation and hosting of OAuth Client ID Metadata Documents (CIMD) for each MCP proxy route. This enables zero-configuration client registration with remote authorization servers.

**Status: ✅ IMPLEMENTED** - See [handler_cimd.go](internal/mcp/handler_cimd.go)

## Normative References

### MCP Authorization Spec (/.docs/mcp/basic/authorization.mdx)

> **Section: Client ID Metadata Documents**
> "MCP clients and authorization servers **SHOULD** support OAuth Client ID Metadata Documents as specified in OAuth Client ID Metadata Document. This approach enables clients to use HTTPS URLs as client identifiers, where the URL points to a JSON document containing client metadata."

> **Section: Implementation Requirements - For MCP Clients**
> - "Clients **MUST** host their metadata document at an HTTPS URL following RFC requirements"
> - "The `client_id` URL **MUST** use the "https" scheme and contain a path component"
> - "The metadata document **MUST** include at least the following properties: `client_id`, `client_name`, `redirect_uris`"
> - "Clients **MUST** ensure the `client_id` value in the metadata matches the document URL exactly"

### OAuth CIMD Draft (/.docs/RFC/draft-ietf-oauth-client-id-metadata-document.txt)

> **Section 3 - Client Identifier**: "Client identifier URLs MUST have an "https" scheme, MUST contain a path component, MUST NOT contain single-dot or double-dot path segments, MUST NOT contain a fragment component"

> **Section 4.1 - Client Metadata**: "The client metadata document MUST contain a client_id property whose value MUST match the URL of the document using simple string comparison"

> **Section 4.4 - Metadata Caching**: "The authorization server MAY cache the client metadata it discovers... SHOULD respect HTTP cache headers"

## Current Implementation

The CIMD hosting is implemented in [handler_cimd.go](internal/mcp/handler_cimd.go:31-57):

```go
// ClientIDMetadata serves per-host Client ID Metadata Documents for MCP server routes
// using auto-discovery mode.
func (h *Handler) ClientIDMetadata(w http.ResponseWriter, r *http.Request) {
    // Validates host against config via h.hosts.UsesAutoDiscovery(hostname)
    // Generates CIMD dynamically based on request host
    // Sets Cache-Control: public, max-age=3600
}
```

**Key implementation details:**
- CIMD served at `/.pomerium/mcp/client/metadata.json` (not `.well-known` - see note below)
- Uses `UsesAutoDiscovery()` from [host_info.go](internal/mcp/host_info.go:122-130) to check eligibility
- Validates hostname against configured routes before generating CIMD (prevents Host header injection)
- Caches response for 1 hour per HTTP cache headers

**Path Decision**: The current path `/.pomerium/mcp/client/metadata.json` is valid per the CIMD spec which states "This specification places no restrictions on what URL is used as a client identifier." The `.well-known` path is conventional but not required.

## Generated Document Format

```json
{
  "client_id": "https://mcp.example.com/.pomerium/mcp/client/metadata.json",
  "client_name": "Pomerium MCP Proxy - mcp.example.com",
  "client_uri": "https://mcp.example.com",
  "redirect_uris": [
    "https://mcp.example.com/.pomerium/mcp/client/oauth/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

### Field Derivation (from handler_cimd.go:92-119)

| Field | Source | Spec Reference |
|-------|--------|----------------|
| `client_id` | Route's `from:` URL + CIMD path | CIMD §3: "MUST match the URL of the document" |
| `client_name` | Policy.Name or generated from hostname | CIMD §4.1: Client metadata property |
| `client_uri` | Route's `from:` URL | OAuth DCR: Client metadata |
| `redirect_uris` | Route's `from:` URL + callback path | CIMD §4.5: "registration of redirect URIs" |
| `grant_types` | Fixed: `["authorization_code", "refresh_token"]` | MCP Auth: Required for token lifecycle |
| `response_types` | Fixed: `["code"]` | OAuth 2.1: Authorization code flow |
| `token_endpoint_auth_method` | Fixed: `"none"` (public client) | CIMD §4.1: No client_secret possible |

## Implementation Tasks

- [x] Create CIMD handler for metadata document path
- [x] Implement CIMD generation from route configuration
- [x] Register handler for all proxy routes
- [x] Ensure proper Content-Type header (`application/json`)
- [x] Add caching headers (CIMD is static per route)
- [x] Generate appropriate `client_name` from route hostname
- [x] Construct proper redirect URI with callback path
- [ ] Handle CORS for cross-origin CIMD fetches (needed for AS fetching CIMD)

## Callback Endpoint

The client OAuth callback endpoint for receiving authorization codes from remote AS:
- [x] Handler at `/.pomerium/mcp/client/oauth/callback` - see [handler_oauth_callback.go](internal/mcp/handler_oauth_callback.go)
- [ ] Wire callback to authorization choreographer (pending [authorization-choreographer](./authorization-choreographer.md))

## Acceptance Criteria

1. ✅ CIMD is served at `{route}/.pomerium/mcp/client/metadata.json` for proxy routes
2. ✅ Document contains all required fields per OAuth CIMD spec (client_id, client_name, redirect_uris)
3. ✅ `client_id` field matches the CIMD URL exactly (simple string comparison)
4. ✅ `redirect_uris` points to valid callback endpoint
5. ⏳ Remote authorization servers can fetch and validate the CIMD (needs E2E testing)
6. ✅ Callback endpoint is available at `{route}/.pomerium/mcp/client/oauth/callback`

## Security Considerations

Per CIMD spec §6 Security Considerations:

| Consideration | Implementation | Status |
|--------------|----------------|--------|
| HTTPS only | All Pomerium routes use HTTPS | ✅ |
| Host header validation | Validated against configured routes before CIMD generation | ✅ |
| State parameter validation | In callback handler | ✅ |
| CSRF protection | Via state parameter binding | ✅ |
| SSRF protection | Uses DomainMatcher allowlist | ✅ |

## References

- [OAuth Client ID Metadata Document Draft](/.docs/RFC/draft-ietf-oauth-client-id-metadata-document.txt)
- [MCP Authorization Spec - Client ID Metadata Documents](/.docs/mcp/basic/authorization.mdx#client-id-metadata-documents)
- [MCP Proxy Epic](./index.md)
- Implementation: [handler_cimd.go](internal/mcp/handler_cimd.go)
- Tests: [handler_cimd_test.go](internal/mcp/handler_cimd_test.go)

## Log

- 2026-02-02: Updated status to implemented; added normative references and implementation details
- 2026-01-26: Issue created from epic breakdown
