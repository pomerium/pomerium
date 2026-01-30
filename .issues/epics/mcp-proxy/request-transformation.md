---
id: request-transformation
title: "Request Transformation and Token Injection"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: high
labels:
  - mcp
  - proxy
  - request-handling
deps:
  - upstream-token-lifecycle
  - authorization-choreographer
---

# Request Transformation and Token Injection

## Summary

Implement request transformation to replace Pomerium-issued tokens with upstream-specific tokens when forwarding requests to remote MCP servers. This includes token injection, header transformation, and proper handling of MCP protocol elements.

## Requirements

From the epic:
> **Request Transformer**: Transforms requests between the client-facing MCP session and upstream:
> - Replaces Pomerium-issued tokens with upstream-specific tokens
> - Maps session identifiers appropriately
> - Handles header transformations (MCP-Session-Id, etc.)

## Request Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Request Transformation                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Incoming Request (from MCP Client)                                 │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ Authorization: Bearer {pomerium_access_token}                │   │
│  │ MCP-Session-Id: {client_session_id}                          │   │
│  │ Content-Type: application/json                               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│                    ┌──────────────────┐                             │
│                    │  Transform       │                             │
│                    │  - Validate      │                             │
│                    │  - Get upstream  │                             │
│                    │    token         │                             │
│                    │  - Replace auth  │                             │
│                    │  - Map headers   │                             │
│                    └──────────────────┘                             │
│                              │                                       │
│                              ▼                                       │
│  Outgoing Request (to Remote MCP Server)                            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ Authorization: Bearer {upstream_access_token}                │   │
│  │ MCP-Session-Id: {upstream_session_id}  (optional mapping)    │   │
│  │ Content-Type: application/json                               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Token Replacement

The core transformation is replacing the Authorization header:

```go
func transformRequest(req *http.Request, upstreamToken string) {
    // Remove Pomerium's token
    req.Header.Del("Authorization")

    // Inject upstream token
    req.Header.Set("Authorization", "Bearer "+upstreamToken)
}
```

**Critical**: The Pomerium-issued token MUST NOT be forwarded to upstream. This prevents token confusion and ensures proper audience binding.

## Header Transformations

### Headers to Transform

| Header | Transformation |
|--------|---------------|
| `Authorization` | Replace with upstream token |
| `MCP-Session-Id` | Map to upstream session (if applicable) |
| `Host` | Update to upstream host |
| `X-Forwarded-*` | Set appropriately |

### Headers to Preserve

| Header | Notes |
|--------|-------|
| `Content-Type` | Pass through |
| `Accept` | Pass through |
| `Content-Length` | Recalculate if body changes |

### Headers to Remove

| Header | Reason |
|--------|--------|
| `X-Pomerium-*` | Internal Pomerium headers |
| Hop-by-hop headers | Per HTTP spec |

## Session ID Mapping

The MCP-Session-Id may need mapping:

```go
type SessionMapping struct {
    ClientSessionID   string  // Session ID from MCP client
    UpstreamSessionID string  // Session ID for upstream server
    RouteID           string
    UpstreamServer    string
    CreatedAt         time.Time
}
```

Options:
1. **Pass-through**: Use same session ID (simple, may leak info)
2. **Mapped**: Generate new upstream session ID (isolated, more complex)
3. **None**: Don't send MCP-Session-Id upstream (if upstream doesn't need it)

## Implementation Tasks

### Token Injection
- [ ] Implement Authorization header replacement
- [ ] Ensure Pomerium token is never forwarded
- [ ] Handle missing upstream token (trigger authorization)
- [ ] Handle token formats (Bearer only for now)

### Header Transformation
- [ ] Implement header rewriting logic
- [ ] Remove Pomerium-internal headers
- [ ] Update Host header
- [ ] Set appropriate X-Forwarded-* headers
- [ ] Remove hop-by-hop headers

### Session Mapping
- [ ] Decide on session ID handling strategy
- [ ] Implement session ID mapping if needed
- [ ] Store mappings persistently if needed

### Request Processing
- [ ] Integrate with proxy request pipeline
- [ ] Handle streaming requests (SSE)
- [ ] Handle large request bodies efficiently
- [ ] Preserve request timing characteristics

### Response Handling
- [ ] Transform upstream responses if needed
- [ ] Map session IDs in responses
- [ ] Handle upstream errors appropriately

## Acceptance Criteria

1. Pomerium tokens are never sent to upstream
2. Upstream tokens are correctly injected
3. Headers are properly transformed
4. Request bodies are preserved exactly
5. Streaming requests work correctly
6. Session IDs are handled consistently
7. No information leakage through headers

## Security Considerations

- NEVER forward Pomerium access tokens upstream
- Strip sensitive headers before forwarding
- Validate upstream token exists before forwarding
- Log transformation errors without exposing tokens

## References

- [MCP Proxy Epic](./index.md)
- [MCP Transports Specification](/.docs/mcp/basic/transports.mdx)

## Log

- 2026-01-26: Issue created from epic breakdown
