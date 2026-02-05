---
id: token-isolation-enforcement
title: "Token Isolation and Security Enforcement"
status: open
created: 2026-01-26
updated: 2026-02-02
priority: critical
labels:
  - mcp
  - proxy
  - security
deps:
  - upstream-token-storage
  - route-configuration-schema
---

# Token Isolation and Security Enforcement

## Summary

Implement and enforce strict token isolation to ensure upstream tokens are never shared across users, sessions, or routes inappropriately. This is critical for preventing security vulnerabilities like confused deputy attacks and privilege escalation.

## Normative References

### MCP Authorization Spec (/.docs/mcp/basic/authorization.mdx)

> **Section: Token Passthrough (Security Best Practices)**
> "MCP servers **MUST NOT** pass through the token it received from the MCP client... The access token used at the upstream API is a separate token, issued by the upstream authorization server."

> **Section: Confused Deputy Problem**
> "Attackers can exploit MCP servers acting as intermediaries to third-party APIs, leading to confused deputy vulnerabilities."

> **Section: Access Token Privilege Restriction**
> "MCP servers **MUST** validate access tokens before processing the request, ensuring the access token is issued specifically for the MCP server... MCP servers **MUST** only accept tokens specifically intended for themselves."

> **Section: Token Requirements**
> "MCP clients **MUST NOT** send tokens to the MCP server other than ones issued by the MCP server's authorization server."

### MCP Security Best Practices (/.docs/mcp/basic/security_best_practices.mdx)

The security best practices document provides guidance on:
- Session hijacking mitigations
- Token theft prevention
- Secure token storage

## Implementation Reasoning

### Why Token Isolation is Critical

The MCP spec explicitly forbids token passthrough and requires audience validation. For Pomerium acting as a proxy:

1. **Pomerium tokens ≠ Upstream tokens**: Tokens issued by Pomerium's AS are for accessing Pomerium, not upstream servers
2. **Per-user isolation**: Upstream tokens must be bound to the authenticated user to prevent confused deputy
3. **Per-route isolation**: Different routes may connect to different upstreams with different trust levels

### Existing Storage Pattern

The current storage in [storage.go](internal/mcp/storage.go:171-189) uses a key format:
```go
// Current: "{host}|{userID}"
key := upstreamTokenKey(host, userID)
```

This needs to be extended to include route for complete isolation:
```go
// Proposed: "{routeID}|{host}|{userID}" or structured key
type TokenKey struct {
    RouteID        string
    UpstreamServer string
    UserID         string
}
```

## Token Binding

Upstream tokens are always bound to the authenticated user:

```
Token Key: (user_id, route_id, upstream_server)
```

- Tokens shared across all sessions for the same user
- User consents once per upstream per route
- Tokens revoked when user logs out
- **Enforced by**: Storage layer key structure + retrieval validation

## Security Invariants (MUST enforce)

| Invariant | Spec Reference | Enforcement Point |
|-----------|----------------|-------------------|
| User A's tokens NEVER accessible to User B | MCP Auth: Confused Deputy | Storage retrieval validation |
| Tokens for Route A MUST NOT be usable for Route B | Epic: Per-route isolation | Token key structure |
| Pomerium tokens MUST NOT be forwarded upstream | MCP Auth: "MUST NOT pass through" | Request transformation |
| Upstream tokens MUST be bound to upstream server | MCP Auth: Audience validation | Resource indicator + storage |

## Implementation Tasks

### Token Storage Isolation
- [ ] Extend token key to include route_id: `(route_id, upstream_server, user_id)`
- [ ] Enforce key structure at storage layer (not bypassable)
- [ ] Add route_id to UpstreamMCPToken protobuf
- [ ] Migrate existing token records (if any)

### Token Retrieval Validation
- [ ] Validate user_id matches authenticated user on retrieval
- [ ] Validate route_id matches current route context
- [ ] Validate upstream_server matches expected resource
- [ ] Reject tokens immediately on any mismatch (fail closed)
- [ ] Log rejection as security event

### Request Transformation (Token Passthrough Prevention)
Per MCP spec: "MUST NOT pass through the token it received"
- [ ] ALWAYS remove incoming Authorization header before forwarding
- [ ] ALWAYS inject upstream-specific token
- [ ] Never expose Pomerium session tokens to upstream
- [ ] Validate this in request transformation tests

### Audit Logging
- [ ] Log token acquisition: (user_id, route_id, upstream, timestamp)
- [ ] Log token usage: (user_id, route_id, upstream, request_path)
- [ ] Log token revocation: (user_id, route_id, upstream, reason)
- [ ] Log isolation violations as SECURITY events (alertable)
- [ ] NEVER log actual token values

## Threat Model

### Confused Deputy Attack

```
Attacker → Pomerium → Upstream
           │
           │ Uses token belonging to different user
           ↓
      PREVENTED BY:
      - User ID in token key (storage isolation)
      - User ID validation on retrieval
      - MCP spec: "MUST validate access tokens"
```

### Token Theft via Route Confusion

```
Attacker → Route A (attacker controlled)
           │
           │ Attempts to use token acquired for Route B
           ↓
      PREVENTED BY:
      - Route ID in token key (storage isolation)
      - Route ID validation on retrieval
      - Epic: "Per-route isolation"
```

### Token Passthrough Attack

```
Malicious Client → Pomerium → Upstream
                   │
                   │ Forwards Pomerium token to upstream
                   ↓
      PREVENTED BY:
      - Always strip incoming Authorization
      - Always inject upstream-specific token
      - MCP spec: "MUST NOT pass through"
```

### Session Hijacking

```
Attacker → Hijacked session → Pomerium
           │
           │ Uses tokens from original user
           ↓
      PREVENTED BY:
      - Pomerium session validation (existing)
      - User ID bound to session (existing)
      - Tokens bound to user (this task)
```

## Testing Requirements

| Test | Validates |
|------|-----------|
| User A cannot retrieve User B's tokens | User isolation |
| Route A tokens not accessible via Route B | Route isolation |
| Pomerium token never forwarded upstream | Passthrough prevention |
| All token operations produce audit logs | Auditability |
| Isolation violation logged as SECURITY | Alertability |

## Acceptance Criteria

1. Tokens strictly isolated by (user, route, upstream)
2. ALL token access produces audit log entry
3. Cross-user token access is impossible (storage-layer enforced)
4. Cross-route token access is impossible (storage-layer enforced)
5. Pomerium tokens NEVER forwarded to upstream (request transformation)
6. Security violations logged at SECURITY level (alertable)
7. Tests cover all threat model scenarios

## References

- [MCP Authorization Spec](/.docs/mcp/basic/authorization.mdx) - Token passthrough, confused deputy
- [MCP Security Best Practices](/.docs/mcp/basic/security_best_practices.mdx)
- [MCP Proxy Epic](./index.md)
- Related: [upstream-resource-indicators](./upstream-resource-indicators.md) - Audience binding
- Implementation: [storage.go](internal/mcp/storage.go) - Current token storage

## Log

- 2026-02-04: Removed service_account binding mode; tokens are always bound to user
- 2026-02-02: Added normative references, threat model, testing requirements
- 2026-01-26: Simplified to user-only token binding (removed per_session option)
- 2026-01-26: Issue created from epic breakdown
