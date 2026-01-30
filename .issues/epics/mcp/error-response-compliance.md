---
id: error-response-compliance
title: "OAuth 2.1 Error Response Compliance"
status: open
created: 2026-01-06
updated: 2026-01-26
priority: low
labels:
  - optional
  - mcp
  - oauth2
  - compliance
deps: []
---

# OAuth 2.1 Error Response Compliance

## Summary

Ensure all error responses from MCP authorization endpoints comply with OAuth 2.1 error response format and codes.

## Spec Requirements

### MCP Spec (authorization.mdx)

The MCP authorization spec references error handling in several places:

1. **Error Handling Section** (lines 487-495): Defines HTTP status codes:
   - 401 Unauthorized: Authorization required or token invalid
   - 403 Forbidden: Invalid scopes or insufficient permissions
   - 400 Bad Request: Malformed authorization request

2. **Token Handling** (lines 471-478): References OAuth 2.1 Section 5.3 for error handling when token validation fails.

3. **Scope Challenge Handling** (lines 497-558): Specifies `HTTP 403 Forbidden` with `WWW-Authenticate` header containing `error="insufficient_scope"` per RFC 6750 Section 3.1.

### OAuth 2.1 (draft-ietf-oauth-v2-1)

**Section 3.2.4 - Token Endpoint Error Response** (lines 1726-1800):
- MUST return HTTP 400 (unless specified otherwise)
- MUST include `error` field with codes: `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`
- MAY return HTTP 401 for `invalid_client` with `WWW-Authenticate` header
- MAY include `error_description` and `error_uri`

**Section 4.1.2.1 - Authorization Endpoint Error Response** (lines 2189-2284):
- MUST NOT redirect if redirect_uri or client_id is invalid
- Otherwise, MUST redirect with error params in query component
- MUST include `error` with codes: `invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`, `temporarily_unavailable`
- MUST include `state` if present in original request
- MAY include `error_description`, `error_uri`, `iss`

**Section 5.3 - Resource Server Error Response** (lines 2774-2869):
- MUST include `WWW-Authenticate` header with `Bearer` scheme
- SHOULD include `error` attribute with reason for failure
- MAY include `error_description` and `error_uri`

### RFC 6750 - Bearer Token Usage

**Section 3 - WWW-Authenticate Response Header Field** (lines 365-433):
- MUST use auth-scheme value `Bearer`
- MAY include `realm`, `scope`, `error`, `error_description`, `error_uri`

**Section 3.1 - Error Codes** (lines 463-498):
- `invalid_request`: HTTP 400 - malformed request
- `invalid_token`: HTTP 401 - expired, revoked, or invalid token
- `insufficient_scope`: HTTP 403 - requires higher privileges

## Current State

The implementation has good token endpoint compliance but lacks authorization endpoint redirect-based errors.

**Error Infrastructure** (`internal/oauth21/error.go`):
- ✅ `oauth21.Error` struct with Code, Description, ErrorURI fields
- ✅ Core error codes: InvalidRequest, InvalidClient, InvalidGrant, UnauthorizedClient, UnsupportedGrantType, InvalidScope
- ⚠️ `oauth21.ErrorResponse()` only accepts error code, not description or error_uri
- ❌ Missing auth endpoint codes: AccessDenied, UnsupportedResponseType, ServerError, TemporarilyUnavailable

**Token Endpoint** (`internal/mcp/handler_token.go`):
- ✅ JSON error response format with `oauth21.ErrorResponse()`
- ✅ Content-Type: application/json
- ✅ Proper error codes for grant failures
- ⚠️ All errors return HTTP 400 (should use 401 for client auth failures)

**Authorization Endpoint** (`internal/mcp/handler_authorization.go`):
- ✅ Direct error responses use `oauth21.ErrorResponse()`
- ❌ No redirect-based error responses
- ❌ State parameter not preserved in error responses

**Resource Server**:
- ✅ WWW-Authenticate header generated for 401 responses
- ✅ Bearer token scheme with Structured Field Values (RFC 8949)
- ❌ Bearer error codes not defined in oauth21 package (invalid_token, insufficient_scope)

## Implementation Tasks

### Authorization Endpoint Errors
- [ ] Return errors via redirect when possible (with redirect_uri)
- [x] Fall back to direct response when redirect not possible
- [ ] Include `error`, `error_description`, `error_uri`, `state` in redirect
- [x] Use correct error codes per OAuth 2.1 (partial - missing auth-specific codes)

### Token Endpoint Errors
- [x] Return JSON error response format
- [ ] Include `error_description` in responses (currently only code)
- [x] Use HTTP 400 for most errors
- [ ] Use HTTP 401 for client authentication errors
- [x] Set `Content-Type: application/json`

### Resource Server Errors
- [x] Return `WWW-Authenticate` header for 401 responses
- [ ] Include `error` code in WWW-Authenticate for token errors
- [ ] Include `error_description` when helpful
- [ ] Define Bearer token error codes (invalid_token, insufficient_scope)

## Error Codes

### Authorization Endpoint
| Code | Description |
|------|-------------|
| `invalid_request` | Missing or invalid parameter |
| `unauthorized_client` | Client not authorized for grant type |
| `access_denied` | Resource owner denied request |
| `unsupported_response_type` | Response type not supported |
| `invalid_scope` | Scope value invalid or unknown |
| `server_error` | Unexpected server error |
| `temporarily_unavailable` | Server temporarily unavailable |

### Token Endpoint
| Code | Description |
|------|-------------|
| `invalid_request` | Missing or invalid parameter |
| `invalid_client` | Client authentication failed |
| `invalid_grant` | Authorization grant invalid |
| `unauthorized_client` | Client not authorized for grant type |
| `unsupported_grant_type` | Grant type not supported |
| `invalid_scope` | Scope value invalid |

## Example Token Error Response

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired"
}
```

## Acceptance Criteria

1. All authorization errors use correct OAuth 2.1 format
2. Token endpoint errors return proper JSON format
3. Error codes match OAuth 2.1 specification
4. WWW-Authenticate headers use proper format
5. Error descriptions are helpful but not leaking sensitive info
6. State parameter is preserved in error redirects

## References

### MCP Specification
- [MCP Authorization Spec - Error Handling](.docs/mcp/basic/authorization.mdx#L487-L495)
- [MCP Authorization Spec - Token Handling](.docs/mcp/basic/authorization.mdx#L471-L478)
- [MCP Authorization Spec - Scope Challenge Handling](.docs/mcp/basic/authorization.mdx#L497-L558)

### OAuth 2.1 (draft-ietf-oauth-v2-1)
- [Section 3.2.4 - Token Endpoint Error Response](.docs/RFC/draft-ietf-oauth-v2-1.txt#L1726-L1800)
- [Section 4.1.2.1 - Authorization Endpoint Error Response](.docs/RFC/draft-ietf-oauth-v2-1.txt#L2189-L2284)
- [Section 5.3 - Resource Server Error Response](.docs/RFC/draft-ietf-oauth-v2-1.txt#L2774-L2869)
- [Section 5.3.1 - WWW-Authenticate Response Header](.docs/RFC/draft-ietf-oauth-v2-1.txt#L2781-L2869)

### RFC 6750 - Bearer Token Usage
- [Section 3 - WWW-Authenticate Response Header Field](.docs/RFC/rfc6750.txt#L365-L433)
- [Section 3.1 - Error Codes](.docs/RFC/rfc6750.txt#L463-L498)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Reviewed - oauth21.ErrorResponse() is used in handler_token.go for token endpoint errors, but comprehensive review of all error paths needed
- 2026-01-26: Comprehensive code review completed:
  - Token endpoint ~95% compliant (missing 401 for client auth, description in responses)
  - Authorization endpoint ~50% compliant (direct errors work, redirect errors missing)
  - WWW-Authenticate header implemented but missing error codes in body
  - Critical gap: no redirect-based error responses from authorization endpoint with state preservation
