---
id: www-authenticate-header
title: "WWW-Authenticate Header with Resource Metadata"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: high
labels:
  - mcp
  - oauth2
  - rfc9728
deps: []
---

# WWW-Authenticate Header with Resource Metadata

## Summary

Implement proper WWW-Authenticate header responses for 401 Unauthorized responses, including the resource metadata URL as specified in RFC 9728.

## Requirement (from MCP Specification)

> MCP servers **MUST** implement one of the following discovery mechanisms:
>
> 1. **WWW-Authenticate Header**: Include the resource metadata URL in the `WWW-Authenticate` HTTP header under `resource_metadata` when returning `401 Unauthorized` responses, as described in RFC 9728 Section 5.1.

> MCP servers **SHOULD** include a `scope` parameter in the `WWW-Authenticate` header as defined in RFC 6750 Section 3 to indicate the scopes required for accessing the resource.

## Current State

The current implementation:
- Returns 401 responses but may not include properly formatted WWW-Authenticate headers
- Does not include `resource_metadata` parameter
- Does not include `scope` guidance in challenges

## Implementation Tasks

- [ ] Add WWW-Authenticate header to all 401 responses
- [ ] Include `resource_metadata` parameter pointing to `/.well-known/oauth-protected-resource`
- [ ] Include `scope` parameter indicating required scopes for the request
- [ ] Include `realm` parameter for the protected resource
- [ ] Handle Bearer token authentication scheme properly
- [ ] Add support for `error` and `error_description` parameters

## Example Response

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         scope="openid offline",
                         realm="mcp"
```

## Example with Insufficient Scope (403)

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
                         scope="files:read files:write",
                         resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         error_description="Additional file write permission required"
```

## Acceptance Criteria

1. All 401 responses include WWW-Authenticate header with Bearer scheme
2. `resource_metadata` parameter is included and points to valid metadata endpoint
3. `scope` parameter provides guidance on required scopes
4. MCP clients can parse the header to discover authorization server
5. Proper RFC 6750 Section 3 compliance for error responses

## References

- [RFC 9728 Section 5.1 - WWW-Authenticate Response](https://datatracker.ietf.org/doc/html/rfc9728#section-5.1)
- [RFC 6750 Section 3 - The WWW-Authenticate Response Header Field](https://datatracker.ietf.org/doc/html/rfc6750#section-3)
- [MCP Authorization - Protected Resource Metadata Discovery](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
