---
id: scope-challenge-handling
title: "Scope Challenge and Step-Up Authorization"
status: open
created: 2026-01-06
updated: 2026-01-06
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

Implement scope challenge handling for insufficient scope errors (HTTP 403) and support step-up authorization flows for incremental consent.

## Requirement (from MCP Specification)

> When a client makes a request with an access token with insufficient scope during runtime operations, the server **SHOULD** respond with:
>
> - `HTTP 403 Forbidden` status code (per RFC 6750 Section 3.1)
> - `WWW-Authenticate` header with the `Bearer` scheme and additional parameters:
>   - `error="insufficient_scope"` - indicating the specific type of authorization failure
>   - `scope="required_scope1 required_scope2"` - specifying the minimum scopes needed for the operation
>   - `resource_metadata` - the URI of the Protected Resource Metadata document
>   - `error_description` (optional) - human-readable description of the error

## Use Case

This enables incremental consent where:
1. Client initially requests minimal scopes
2. Client attempts operation requiring additional scope
3. Server returns 403 with required scopes
4. Client initiates step-up authorization with new scope set
5. User grants additional permissions
6. Client retries operation with new token

## Current State

The current implementation does not differentiate between authentication failures (401) and authorization/scope failures (403), and does not provide scope guidance in error responses.

## Implementation Tasks

- [ ] Distinguish between 401 (authentication) and 403 (authorization) responses
- [ ] Add scope-to-endpoint/operation mapping configuration
- [ ] Return HTTP 403 with `insufficient_scope` error for scope failures
- [ ] Include required scopes in WWW-Authenticate header
- [ ] Include `resource_metadata` in 403 responses
- [ ] Support scope minimization (advertise minimal scopes in `scopes_supported`)
- [ ] Document scope requirements per MCP operation
- [ ] Add support for scope inheritance/hierarchy if applicable

## Example 403 Response

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
                         scope="files:read files:write user:profile",
                         resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         error_description="Additional file write permission required"
```

## Scope Selection Strategy

From the MCP specification:
> MCP clients **SHOULD** follow this priority order for scope selection:
>
> 1. **Use `scope` parameter** from the initial `WWW-Authenticate` header in the 401 response, if provided
> 2. **If `scope` is not available**, use all scopes defined in `scopes_supported` from the Protected Resource Metadata document

## Acceptance Criteria

1. Scope requirements are defined per MCP operation
2. 403 responses are returned for insufficient scope (not 401)
3. WWW-Authenticate header includes required scopes
4. Step-up authorization flow works end-to-end
5. Retry after scope upgrade succeeds
6. Documentation covers scope requirements

## References

- [RFC 6750 Section 3.1](/.docs/RFC/rfc6750.txt)
- [MCP Authorization - Scope Challenge Handling](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
