---
id: openid-connect-discovery
title: "OpenID Connect Discovery 1.0 Support"
status: cancelled
created: 2026-01-06
updated: 2026-01-26
priority: medium
labels:
  - optional
  - mcp
  - oauth2
  - openid
deps: []
---

# OpenID Connect Discovery 1.0 Support

## Summary

Implement OpenID Connect Discovery 1.0 as an alternative to OAuth 2.0 Authorization Server Metadata for authorization server discovery.

## Requirement (from MCP Specification)

> MCP authorization servers **MUST** provide at least one of the following discovery mechanisms:
> - OAuth 2.0 Authorization Server Metadata ([RFC8414](/.docs/RFC/rfc8414.txt))
> - [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
>
> MCP clients **MUST** support both discovery mechanisms to obtain the information required to interact with the authorization server.

> Authorization servers providing OpenID Connect Discovery 1.0 **MUST** include `code_challenge_methods_supported` in their metadata to ensure MCP compatibility.

## Current State

The current implementation provides OAuth 2.0 Authorization Server Metadata at `/.well-known/oauth-authorization-server` but does not serve OpenID Connect Discovery at `/.well-known/openid-configuration`.

## Implementation Tasks

- [ ] Add `/.well-known/openid-configuration` endpoint
- [ ] Include all required OpenID Provider Metadata fields
- [ ] Include `code_challenge_methods_supported` (required for MCP)
- [ ] Add OpenID-specific metadata fields (e.g., `userinfo_endpoint`, `id_token_signing_alg_values_supported`)
- [ ] Ensure consistency between OAuth AS metadata and OIDC discovery
- [ ] Support both root and path-appended discovery URLs
- [ ] Add tests for discovery endpoint

## OpenID Connect Metadata Fields

```json
{
  "issuer": "https://pomerium.example.com",
  "authorization_endpoint": "https://pomerium.example.com/.pomerium/mcp/authorize",
  "token_endpoint": "https://pomerium.example.com/.pomerium/mcp/token",
  "userinfo_endpoint": "https://pomerium.example.com/.pomerium/mcp/userinfo",
  "jwks_uri": "https://pomerium.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://pomerium.example.com/.pomerium/mcp/register",
  "scopes_supported": ["openid", "offline", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"]
}
```

## Discovery URL Priority

For issuer URLs with path components (e.g., `https://auth.example.com/tenant1`), MCP clients try:
1. `https://auth.example.com/.well-known/oauth-authorization-server/tenant1`
2. `https://auth.example.com/.well-known/openid-configuration/tenant1`
3. `https://auth.example.com/tenant1/.well-known/openid-configuration`

## Acceptance Criteria

1. `/.well-known/openid-configuration` returns valid OIDC metadata
2. `code_challenge_methods_supported` is included
3. All required OIDC Provider Metadata fields are present
4. Metadata is consistent with OAuth AS metadata
5. Path-appended discovery URLs work correctly

## References

- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 8414 Section 5 - Compatibility Notes](/.docs/RFC/rfc8414.txt)
- [MCP Authorization - Authorization Server Metadata Discovery](/.docs/mcp/basic/authorization.mdx)
- MCP Spec Change: [PR #797](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/797)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Verified not implemented - only `/.well-known/oauth-authorization-server` is served, no OIDC discovery
- 2026-01-26: Cancelled - MCP spec requires "at least one" of RFC8414 or OIDC Discovery; RFC8414 is already implemented via `/.well-known/oauth-authorization-server` endpoint, making this optional feature unnecessary
