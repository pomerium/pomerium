---
id: mcp-oauth2-authorization-server
title: "MCP OAuth 2.1 Authorization Server Implementation"
status: open
created: 2026-01-06
updated: 2026-01-13
priority: high
owner: ""
labels:
  - mcp
  - oauth2
  - security
  - authorization
---

# Epic: MCP OAuth 2.1 Authorization Server Implementation

## Overview

This epic tracks the implementation of a fully compliant MCP (Model Context Protocol) OAuth 2.1 Authorization Server for Pomerium. The goal is to enable Pomerium to act as an MCP authorization server that allows MCP clients to securely access protected MCP servers through Pomerium's infrastructure.

## Background

The Model Context Protocol (MCP) is an open protocol that enables seamless integration between LLM applications and external data sources/tools. MCP defines a comprehensive authorization framework based on OAuth 2.1 for HTTP-based transports.

### Current State

The current implementation (`/internal/mcp/`) provides:
- Basic OAuth 2.1 Authorization Code flow with PKCE support
- Dynamic Client Registration (RFC 7591)
- Protected Resource Metadata (RFC 9728)
- Authorization Server Metadata (RFC 8414)
- Token endpoint with authorization_code grant
- Client secret authentication methods
- Route listing and connection management

### Target State (MCP Specification 2025-11-25)

Full compliance with the MCP Authorization specification requires implementing additional features and ensuring alignment with the referenced RFCs and OAuth 2.1 draft specification.

## Reference Documentation

- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [OAuth 2.1 Draft](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](/.docs/RFC/rfc9728.txt)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](/.docs/RFC/rfc8414.txt)
- [RFC 7591 - OAuth 2.0 Dynamic Client Registration](/.docs/RFC/rfc7591.txt)
- [RFC 8707 - Resource Indicators for OAuth 2.0](/.docs/RFC/rfc8707.txt)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](/.docs/RFC/rfc6750.txt)

## Issues

### Required by MCP Spec (MUST)

| Issue | Title | Status | Priority | Spec Reference |
|-------|-------|--------|----------|----------------|
| [resource-indicator-support](./resource-indicator-support.md) | RFC 8707 Resource Indicators | open | high | MCP Auth: "MUST implement" |
| [token-audience-validation](./token-audience-validation.md) | Token Audience Binding and Validation | open | critical | MCP Auth: "MUST validate" |
| [dns-rebinding-protection](./dns-rebinding-protection.md) | DNS Rebinding Attack Protection | open | critical | MCP Transports: "MUST validate Origin" |
| [www-authenticate-header](./www-authenticate-header.md) | WWW-Authenticate Header with Resource Metadata | **in_progress** | high | MCP Auth: "MUST implement" (resource_metadata) |

### Recommended by MCP Spec (SHOULD)

| Issue | Title | Status | Priority | Spec Reference |
|-------|-------|--------|----------|----------------|
| [client-id-metadata-documents](./client-id-metadata-documents.md) | OAuth Client ID Metadata Documents Support | **completed** | high | MCP Auth: "SHOULD support" |
| [scope-challenge-handling](./scope-challenge-handling.md) | Scope Challenge and Step-Up Authorization | open | medium | MCP Auth: "SHOULD respond" (insufficient_scope) |
| [confused-deputy-mitigation](./confused-deputy-mitigation.md) | Confused Deputy Attack Mitigation | open | high | MCP Auth: "MUST" for proxy servers |

### Optional (MAY or not in MCP spec)

These features are not explicitly required by the MCP specification but may be useful enhancements.

| Issue | Title | Status | Priority | Notes |
|-------|-------|--------|----------|-------|
| [session-management](./session-management.md) | MCP Session Management (MCP-Session-Id) | open | high | MCP Transports: "MAY assign" |
| [openid-connect-discovery](./openid-connect-discovery.md) | OpenID Connect Discovery 1.0 Support | open | medium | Optional: OAuth AS metadata already satisfies MUST |
| [mcp-refresh-token-and-session-lifecycle](./mcp-refresh-token-and-session-lifecycle.md) | Refresh Token Support and Session Lifecycle | open | critical | Not in MCP spec (OAuth 2.1 feature) |
| [token-introspection](./token-introspection.md) | Token Introspection Endpoint (RFC 7662) | open | medium | Not in MCP spec |
| [access-token-revocation](./access-token-revocation.md) | Access Token Revocation (RFC 7009) | open | low | Not in MCP spec |
| [refresh-token-revocation](./refresh-token-revocation.md) | Refresh Token Revocation (RFC 7009) | open | medium | Not in MCP spec |
| [token-security-hardening](./token-security-hardening.md) | Token Storage and Transmission Security | open | high | General OAuth best practices |
| [streamable-http-transport](./streamable-http-transport.md) | Streamable HTTP Transport (SSE) | open | medium | MCP Transports: SHOULD/MAY for SSE |
| [client-id-metadata-trust-policy](./client-id-metadata-trust-policy.md) | Client ID Metadata Trust Policy | **completed** | medium | Enhancement (allowlist) |
| [client-registration-validation](./client-registration-validation.md) | Enhanced Client Registration Validation | open | medium | Enhancement beyond RFC 7591 |
| [error-response-compliance](./error-response-compliance.md) | OAuth 2.1 Error Response Compliance | open | low | General OAuth compliance |
| [remove-placeholder-scopes](./remove-placeholder-scopes.md) | Remove Placeholder Scopes from Metadata | open | low | Cleanup task |

## Success Criteria

1. Pass MCP protocol compliance validation tests
2. Successfully integrate with reference MCP clients (e.g., Claude Desktop, mcp-cli)
3. All security requirements from MCP Authorization specification implemented
4. Complete test coverage for OAuth 2.1 authorization flows
5. Documentation for MCP server operators

## Log

- 2026-01-06: Epic created with initial gap analysis between MCP spec and current implementation
- 2026-01-13: Cross-checked issues against current implementation and normative docs:
  - `client-id-metadata-documents`: Updated to **completed** - fully implemented in `internal/mcp/client_id_metadata.go`
  - `client-id-metadata-trust-policy`: Updated to **completed** - implemented via `DomainMatcher`
  - `www-authenticate-header`: Updated to **in_progress** - `resource_metadata` implemented, `scope` missing
  - Updated current state details for: `dns-rebinding-protection`, `token-revocation`, `protocol-version-header`, `mcp-refresh-token-and-session-lifecycle`
- 2026-01-13: Split `token-revocation` into two issues:
  - `access-token-revocation` (RFC 7009 SHOULD, priority: low)
  - `refresh-token-revocation` (RFC 7009 MUST, priority: medium, depends on refresh token support)
- 2026-01-13: Added `remove-placeholder-scopes` - remove unused `["openid", "offline"]` from metadata
- 2026-01-13: Reorganized issues by MCP spec requirement level (MUST/SHOULD/optional) and added "optional" label to non-spec-required tickets
- 2026-01-13: Removed `protocol-version-header` - MCP-Protocol-Version validation is upstream MCP server's responsibility, not gateway's
