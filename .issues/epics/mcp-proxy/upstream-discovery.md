---
id: upstream-discovery
title: "Upstream Authorization Server Discovery"
status: open
created: 2026-01-26
updated: 2026-01-26
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

## Requirements

From the epic:
> **Zero-Knowledge Discovery**: Pomerium should work with any compliant MCP server without prior knowledge of its authorization server

## Discovery Flow

When Pomerium (acting as MCP client) first connects to a remote MCP server:

```
1. Initial Request  → Unauthenticated MCP request to upstream
                      ↓
2. Receive 401      → Parse WWW-Authenticate header for:
                      - resource_metadata URL (preferred)
                      - Required scope parameter
                      ↓
3. Fetch Protected  → GET {resource_metadata} or
   Resource Meta      GET {upstream}/.well-known/oauth-protected-resource
                      ↓
4. Extract AS       → Parse authorization_servers array from metadata
                      ↓
5. Fetch AS Meta    → GET {as}/.well-known/oauth-authorization-server or
                      GET {as}/.well-known/openid-configuration
                      ↓
6. Cache Results    → Store for subsequent requests
```

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

Key fields to extract:
- `authorization_endpoint` - For initiating OAuth flow
- `token_endpoint` - For token exchange
- `code_challenge_methods_supported` - To determine PKCE support
- `client_id_metadata_document_supported` - To confirm CIMD support

## Implementation Tasks

### WWW-Authenticate Header Parsing
- [ ] Parse `resource_metadata` parameter from WWW-Authenticate
- [ ] Parse `scope` parameter for required scopes
- [ ] Parse `error` and `error_description` for debugging

### Protected Resource Metadata
- [ ] Implement RFC 9728 metadata fetch from `resource_metadata` URL
- [ ] Implement fallback to `/.well-known/oauth-protected-resource`
- [ ] Parse and validate `authorization_servers` array
- [ ] Extract `scopes_supported` for scope negotiation

### Authorization Server Metadata
- [ ] Implement RFC 8414 metadata fetch from `/.well-known/oauth-authorization-server`
- [ ] Implement fallback to OpenID Connect `/.well-known/openid-configuration`
- [ ] Parse authorization and token endpoints
- [ ] Detect PKCE support from `code_challenge_methods_supported`
- [ ] Detect CIMD support from `client_id_metadata_document_supported`
- [ ] Verify AS supports required grant types

### Caching
- [ ] Cache Protected Resource Metadata per upstream server URL
- [ ] Cache Authorization Server Metadata per AS issuer URL
- [ ] Respect HTTP cache headers from discovery endpoints
- [ ] Implement cache invalidation on authorization failures
- [ ] Set reasonable TTL for cached metadata

### Error Handling
- [ ] Handle network failures during discovery
- [ ] Handle invalid/malformed metadata responses
- [ ] Handle missing required fields
- [ ] Fall back gracefully when discovery fails
- [ ] Provide clear error messages for debugging

## Acceptance Criteria

1. Pomerium discovers authorization requirements from any RFC 9728-compliant server
2. WWW-Authenticate header is parsed correctly
3. Protected Resource Metadata is fetched and validated
4. Authorization Server Metadata is fetched and validated
5. Discovery results are cached appropriately
6. Cache invalidation works on authorization failures
7. Fallback discovery endpoints work when primary fails
8. Clear errors when upstream doesn't support required features

## References

- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](/.docs/RFC/rfc9728.txt)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](/.docs/RFC/rfc8414.txt)
- [MCP Proxy Epic](./index.md)

## Log

- 2026-01-26: Issue created from epic breakdown
