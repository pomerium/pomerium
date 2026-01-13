---
id: www-authenticate-header
title: "WWW-Authenticate Header with Resource Metadata"
status: in_progress
created: 2026-01-06
updated: 2026-01-13
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

**PARTIALLY IMPLEMENTED.** The `SetWWWAuthenticateHeader()` function exists in `internal/mcp/handler_metadata.go:217` and is used by the authorize service (`authorize/check_response.go:112,266`).

Current implementation:
```go
func SetWWWAuthenticateHeader(dst http.Header, host string) error {
    dict := sfv.Dictionary{
        {
            Key:  "resource_metadata",
            Item: sfv.Item{Value: ProtectedResourceMetadataURL(host)},
        },
    }
    txt, err := sfv.EncodeDictionary(dict)
    // ...
    dst.Set("www-authenticate", `Bearer `+txt)
    return nil
}
```

**What's implemented:**
- ✅ Returns 401 responses with WWW-Authenticate header for MCP server routes
- ✅ Includes `resource_metadata` parameter pointing to `/.well-known/oauth-protected-resource`
- ✅ Uses RFC 8941 Structured Field Values for proper encoding

**What's missing:**
- ❌ Does not include `scope` parameter (SHOULD per MCP spec)
- ❌ Does not include `realm` parameter
- ❌ Does not include `error` and `error_description` for 403 responses

## Implementation Tasks

- [x] Add WWW-Authenticate header to all 401 responses
- [x] Include `resource_metadata` parameter pointing to `/.well-known/oauth-protected-resource`
- [ ] Include `scope` parameter indicating required scopes for the request
- [ ] Include `realm` parameter for the protected resource
- [x] Handle Bearer token authentication scheme properly
- [ ] Add support for `error` and `error_description` parameters (for 403 insufficient_scope)

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

1. ✅ All 401 responses include WWW-Authenticate header with Bearer scheme
2. ✅ `resource_metadata` parameter is included and points to valid metadata endpoint
3. ❌ `scope` parameter provides guidance on required scopes (not yet implemented)
4. ✅ MCP clients can parse the header to discover authorization server
5. ❌ Proper RFC 6750 Section 3 compliance for error responses (missing scope, error, error_description)

## Related Files

| File | Purpose |
|------|---------|
| `internal/mcp/handler_metadata.go` | `SetWWWAuthenticateHeader()` function |
| `authorize/check_response.go` | Calls `SetWWWAuthenticateHeader()` on 401 responses |
| `internal/mcp/handler_metadata_test.go` | Unit tests for WWW-Authenticate header |

## References

- [RFC 9728 Section 5.1 - WWW-Authenticate Response](/.docs/RFC/rfc9728.txt)
- [RFC 6750 Section 3 - The WWW-Authenticate Response Header Field](/.docs/RFC/rfc6750.txt)
- [MCP Authorization - Protected Resource Metadata Discovery](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Updated status to in_progress - `resource_metadata` implemented, `scope` parameter still missing
