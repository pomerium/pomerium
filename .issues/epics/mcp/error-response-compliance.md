---
id: error-response-compliance
title: "OAuth 2.1 Error Response Compliance"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: low
labels:
  - mcp
  - oauth2
  - compliance
deps: []
---

# OAuth 2.1 Error Response Compliance

## Summary

Ensure all error responses from MCP authorization endpoints comply with OAuth 2.1 error response format and codes.

## Requirement

OAuth 2.1 defines specific error response formats for different endpoints:
- Authorization endpoint errors (redirect or direct response)
- Token endpoint errors
- Resource server errors (WWW-Authenticate header)

## Current State

The current implementation uses `oauth21.ErrorResponse()` for some errors but needs review for complete compliance.

## Implementation Tasks

### Authorization Endpoint Errors
- [ ] Return errors via redirect when possible (with redirect_uri)
- [ ] Fall back to direct response when redirect not possible
- [ ] Include `error`, `error_description`, `error_uri`, `state` in redirect
- [ ] Use correct error codes per OAuth 2.1

### Token Endpoint Errors
- [ ] Return JSON error response format
- [ ] Include `error` and `error_description`
- [ ] Use HTTP 400 for most errors
- [ ] Use HTTP 401 for client authentication errors
- [ ] Set `Content-Type: application/json`

### Resource Server Errors
- [ ] Return `WWW-Authenticate` header for 401 responses
- [ ] Include `error` code in WWW-Authenticate
- [ ] Include `error_description` when helpful
- [ ] Use correct Bearer token error codes

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

- [OAuth 2.1 Section 4.1.2.1 - Authorization Error Response](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [OAuth 2.1 Section 4.3.3 - Token Error Response](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [RFC 6750 Section 3 - WWW-Authenticate Response](/.docs/RFC/rfc6750.txt)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
