---
id: per-route-cimd-hosting
title: "Auto-Generated Per-Route Client ID Metadata Documents"
status: open
created: 2026-01-26
updated: 2026-01-26
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

## Requirements

From the epic:
> Pomerium automatically generates and hosts a CIMD for this route at:
> `https://mcp.example.com/.well-known/mcp-client-metadata.json`

Each proxy route acts as a separate OAuth client to remote servers, providing:
- **Token Isolation**: Tokens acquired via one route don't leak to other routes
- **Separate Consent**: Users can grant different permissions per route
- **Clear Attribution**: Remote servers see which Pomerium route is accessing them

## Generated Document Format

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

### Field Derivation

| Field | Source |
|-------|--------|
| `client_id` | Route's `from:` URL + `/.well-known/mcp-client-metadata.json` |
| `client_name` | Generated from route hostname |
| `client_uri` | Route's `from:` URL |
| `redirect_uris` | Route's `from:` URL + `/.pomerium/oauth/callback` |
| `grant_types` | Fixed: `["authorization_code", "refresh_token"]` |
| `response_types` | Fixed: `["code"]` |
| `token_endpoint_auth_method` | Fixed: `"none"` (public client) |

## Implementation Tasks

- [ ] Create CIMD handler for `/.well-known/mcp-client-metadata.json` path
- [ ] Implement CIMD generation from route configuration
- [ ] Register handler for all proxy routes
- [ ] Ensure proper Content-Type header (`application/json`)
- [ ] Add caching headers (CIMD is static per route)
- [ ] Handle CORS for cross-origin CIMD fetches
- [ ] Generate appropriate `client_name` from route hostname
- [ ] Construct proper redirect URI with callback path

## Callback Endpoint

This task also requires implementing the OAuth callback endpoint:
- [ ] Create handler at `/.pomerium/oauth/callback` for each proxy route
- [ ] Handler receives authorization code from remote AS
- [ ] Wire callback to authorization choreographer

## Acceptance Criteria

1. CIMD is served at `{route}/.well-known/mcp-client-metadata.json` for proxy routes
2. Document contains all required fields per OAuth CIMD spec
3. `client_id` field matches the CIMD URL exactly
4. `redirect_uris` points to valid callback endpoint
5. Remote authorization servers can fetch and validate the CIMD
6. Callback endpoint is available at `{route}/.pomerium/oauth/callback`

## Security Considerations

- CIMD must be served over HTTPS only
- Callback endpoint must validate state parameter
- Callback must be protected against CSRF

## References

- [OAuth Client ID Metadata Document Draft](/.docs/RFC/draft-ietf-oauth-client-id-metadata-document.txt)
- [MCP Proxy Epic](./index.md)
- [Client ID Metadata Documents (MCP Epic)](../mcp/client-id-metadata-documents.md)

## Log

- 2026-01-26: Issue created from epic breakdown
