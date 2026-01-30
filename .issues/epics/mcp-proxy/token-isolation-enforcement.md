---
id: token-isolation-enforcement
title: "Token Isolation and Security Enforcement"
status: open
created: 2026-01-26
updated: 2026-01-26
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

## Requirements

From the epic:
> **Token Isolation**:
> - Upstream tokens MUST be bound to the authenticated user
> - Tokens MUST NOT be shared across users
> - Tokens are cached per-user, per-route, per-upstream for proper isolation
> - Service account mode requires explicit opt-in and audit logging

## Token Binding Modes

### Per-User Binding (Default)

```
Token Key: (user_id, route_id, upstream_server)
```

- Tokens shared across all sessions for the same user
- User consents once per upstream per route
- Best for typical usage patterns
- Tokens revoked when user logs out

### Service Account Binding

```
Token Key: (route_id, upstream_server)
```

- Single shared token for all requests
- No user identity delegation
- **Requires explicit configuration**
- **Requires audit logging**
- Best for internal services or batch operations

## Security Invariants

These MUST be enforced at all times:

1. **User Isolation**: User A's tokens MUST NEVER be accessible to User B
2. **Route Isolation**: Tokens for Route A MUST NOT be usable for Route B
3. **No Token Passthrough**: Pomerium-issued tokens MUST NOT be forwarded upstream
4. **Audience Binding**: Upstream tokens MUST be bound to the specific upstream server

## Implementation Tasks

### Token Storage Isolation
- [ ] Enforce key structure includes user ID
- [ ] Prevent cross-user token access in storage layer
- [ ] Audit log all token access

### Token Retrieval Validation
- [ ] Validate user ID matches on token retrieval
- [ ] Validate route ID matches
- [ ] Reject tokens with mismatched binding

### Service Account Mode
- [ ] Require explicit `token_binding: service_account` in config
- [ ] Log warning when service account mode is enabled
- [ ] Add audit log entry for every request using service account token
- [ ] Document security implications

### Cross-Request Validation
- [ ] Verify token belongs to current user on every use
- [ ] Prevent token injection via request manipulation
- [ ] Validate upstream server matches token audience

### Audit Logging
- [ ] Log token acquisition with user/session context
- [ ] Log token usage (without token values)
- [ ] Log token revocation
- [ ] Log any isolation violations (security events)

## Threat Model

### Confused Deputy Attack

```
Attacker → Pomerium → Upstream
           │
           │ Uses token belonging to different user
           ↓
      PREVENTED BY: User ID validation on token retrieval
```

### Token Theft via Route Confusion

```
Attacker → Route A (attacker controlled)
           │
           │ Steals token acquired for Route B
           ↓
      PREVENTED BY: Route ID included in token key
```

### Session Hijacking

```
Attacker → Hijacked session
           │
           │ Uses tokens from original session
           ↓
      PREVENTED BY: Pomerium session validation + user binding
```

## Testing Requirements

- [ ] Test user A cannot access user B's tokens
- [ ] Test route A tokens not accessible via route B
- [ ] Test service account mode requires explicit config
- [ ] Test audit logging captures all token operations
- [ ] Test token binding is validated on every use

## Acceptance Criteria

1. Tokens are strictly isolated by user (default)
2. Service account mode requires explicit opt-in
3. All token access is audit logged
4. Cross-user token access is impossible
5. Token binding is enforced at storage and retrieval layers
6. Security events (violations) are logged and alertable

## References

- [MCP Security Best Practices](/.docs/mcp/basic/security_best_practices.mdx)
- [Confused Deputy Mitigation](../mcp/confused-deputy-mitigation.md)
- [MCP Proxy Epic](./index.md)

## Log

- 2026-01-26: Simplified to user-only token binding (removed per_session option)
- 2026-01-26: Issue created from epic breakdown
