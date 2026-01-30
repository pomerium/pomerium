---
id: upstream-error-propagation
title: "Upstream Error Propagation"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: medium
labels:
  - mcp
  - proxy
  - error-handling
deps:
  - request-transformation
---

# Upstream Error Propagation

## Summary

Implement transparent error propagation from upstream MCP servers to clients. Per the epic decision, authorization failures should be passed through transparently to enable proper client handling.

## Requirements

From the epic (Open Questions):
> **Error Propagation**: How should authorization failures from upstream be communicated to clients?
>
> Answer: Transparent passthrough

## Error Categories

### Authorization Errors (401/403)

These require special handling:

| Upstream Response | Proxy Action |
|-------------------|--------------|
| 401 (no cached token) | Initiate authorization flow |
| 401 (with cached token) | Refresh/re-authorize, then retry |
| 403 `insufficient_scope` | Re-authorize with additional scopes |
| 403 (other) | Pass through to client |

### Other Errors

Pass through transparently:

| Upstream Response | Proxy Action |
|-------------------|--------------|
| 400 Bad Request | Pass through |
| 404 Not Found | Pass through |
| 500 Server Error | Pass through |
| Network failures | Convert to 502 Bad Gateway |

## Error Response Transformation

When passing errors through, consider:

```
Upstream Error Response:
{
  "error": "insufficient_scope",
  "error_description": "The access token lacks required scope",
  "scope": "mcp:admin"
}

Client Receives:
{
  "error": "insufficient_scope",
  "error_description": "The access token lacks required scope",
  "scope": "mcp:admin"
}
```

The response should be passed through without modification, allowing the MCP client to understand and potentially handle the error.

## WWW-Authenticate Header Handling

When upstream returns 401 with WWW-Authenticate:

```
WWW-Authenticate: Bearer realm="example",
  error="invalid_token",
  error_description="The access token expired",
  scope="mcp:read mcp:write"
```

Options:
1. **Intercept**: Handle authorization transparently (default)
2. **Pass-through**: After exhausting retry options, pass to client

## Implementation Tasks

### Error Detection
- [ ] Detect 401 Unauthorized responses
- [ ] Parse WWW-Authenticate header
- [ ] Detect 403 Forbidden with error codes
- [ ] Detect insufficient_scope errors

### Retry Logic
- [ ] Implement retry after token refresh
- [ ] Implement retry after re-authorization
- [ ] Limit retry attempts to prevent loops
- [ ] Track retry state per request

### Error Passthrough
- [ ] Pass through non-auth errors transparently
- [ ] Preserve error response bodies
- [ ] Preserve relevant headers
- [ ] Handle binary/streaming error responses

### Network Error Handling
- [ ] Convert network failures to 502 Bad Gateway
- [ ] Convert timeouts to 504 Gateway Timeout
- [ ] Include appropriate error details
- [ ] Don't expose internal network topology

### Logging
- [ ] Log upstream errors for debugging
- [ ] Don't log sensitive error details
- [ ] Include correlation IDs
- [ ] Track error patterns for monitoring

## Error Flow Example

```
┌─────────┐        ┌──────────┐        ┌──────────┐
│ Client  │        │ Pomerium │        │ Upstream │
└────┬────┘        └────┬─────┘        └────┬─────┘
     │                  │                   │
     │ MCP Request      │                   │
     │─────────────────>│                   │
     │                  │ Forward (expired) │
     │                  │──────────────────>│
     │                  │                   │
     │                  │ 401 Unauthorized  │
     │                  │<──────────────────│
     │                  │                   │
     │                  │ Refresh token     │
     │                  │───────────────────│
     │                  │                   │
     │                  │ New access token  │
     │                  │<──────────────────│
     │                  │                   │
     │                  │ Retry with new    │
     │                  │ token             │
     │                  │──────────────────>│
     │                  │                   │
     │                  │ 200 OK            │
     │                  │<──────────────────│
     │                  │                   │
     │ 200 OK           │                   │
     │<─────────────────│                   │
     │                  │                   │
```

## Acceptance Criteria

1. Authorization errors trigger token refresh/re-auth automatically
2. Non-auth errors pass through transparently
3. Error response bodies are preserved
4. Network failures become 502/504 responses
5. Retry logic doesn't create infinite loops
6. Clients can understand and handle passed-through errors
7. Error logging aids debugging without exposing secrets

## References

- [RFC 6750 - OAuth 2.0 Bearer Token Usage](/.docs/RFC/rfc6750.txt) (error codes)
- [MCP Proxy Epic](./index.md)

## Log

- 2026-01-26: Issue created from epic breakdown
