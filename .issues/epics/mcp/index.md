---
id: mcp-oauth2-authorization-server
title: "MCP OAuth 2.1 Authorization Server Implementation"
status: open
created: 2026-01-06
updated: 2026-01-06
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
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 7591 - OAuth 2.0 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)

## Issues

### Core Authorization

| Issue | Title | Status | Priority |
|-------|-------|--------|----------|
| [mcp-refresh-token-and-session-lifecycle](./mcp-refresh-token-and-session-lifecycle.md) | MCP Refresh Token Support and Session Lifecycle Integration | open | critical |
| [resource-indicator-support](./resource-indicator-support.md) | Implement RFC 8707 Resource Indicators | open | high |
| [token-introspection](./token-introspection.md) | Implement Token Introspection Endpoint (RFC 7662) | open | medium |
| [token-revocation](./token-revocation.md) | Complete Token Revocation Implementation | open | medium |
| [token-audience-validation](./token-audience-validation.md) | Token Audience Binding and Validation | open | critical |

### Discovery & Metadata

| Issue | Title | Status | Priority |
|-------|-------|--------|----------|
| [openid-connect-discovery](./openid-connect-discovery.md) | OpenID Connect Discovery 1.0 Support | open | medium |
| [www-authenticate-header](./www-authenticate-header.md) | WWW-Authenticate Header with Resource Metadata | open | high |
| [scope-challenge-handling](./scope-challenge-handling.md) | Scope Challenge and Step-Up Authorization | open | medium |

### Client Registration

| Issue | Title | Status | Priority |
|-------|-------|--------|----------|
| [client-id-metadata-documents](./client-id-metadata-documents.md) | OAuth Client ID Metadata Documents Support | open | high |
| [client-registration-validation](./client-registration-validation.md) | Enhanced Client Registration Validation | open | medium |

### Security Hardening

| Issue | Title | Status | Priority |
|-------|-------|--------|----------|
| [dns-rebinding-protection](./dns-rebinding-protection.md) | DNS Rebinding Attack Protection | open | critical |
| [session-management](./session-management.md) | MCP Session Management (MCP-Session-Id) | open | high |
| [confused-deputy-mitigation](./confused-deputy-mitigation.md) | Confused Deputy Attack Mitigation | open | high |
| [token-security-hardening](./token-security-hardening.md) | Token Storage and Transmission Security | open | high |

### Protocol Compliance

| Issue | Title | Status | Priority |
|-------|-------|--------|----------|
| [protocol-version-header](./protocol-version-header.md) | MCP Protocol Version Header Support | open | medium |
| [streamable-http-transport](./streamable-http-transport.md) | Streamable HTTP Transport Compliance | open | medium |
| [error-response-compliance](./error-response-compliance.md) | OAuth 2.1 Error Response Compliance | open | low |

## Success Criteria

1. Pass MCP protocol compliance validation tests
2. Successfully integrate with reference MCP clients (e.g., Claude Desktop, mcp-cli)
3. All security requirements from MCP Authorization specification implemented
4. Complete test coverage for OAuth 2.1 authorization flows
5. Documentation for MCP server operators

## Log

- 2026-01-06: Epic created with initial gap analysis between MCP spec and current implementation
