---
id: upstream-token-lifecycle
title: "Upstream Token Lifecycle Management"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: high
labels:
  - mcp
  - proxy
  - token-management
deps:
  - upstream-token-storage
  - upstream-oauth-client-flow
---

# Upstream Token Lifecycle Management

## Summary

Implement comprehensive lifecycle management for upstream tokens including caching, proactive refresh, and revocation. This ensures tokens are always valid when needed and properly cleaned up when no longer required.

## Requirements

From the epic:
> **Token Caching**: Storing tokens per-user/per-upstream with appropriate TTLs
> **Token Refresh**: Proactively refreshing tokens before expiration
> **Token Revocation**: Cleaning up tokens on session termination

## Token Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                      Token Lifecycle                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ Acquired │───>│  Active  │───>│ Expiring │───>│ Expired  │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│       │               │               │               │         │
│       │               │               │               │         │
│       ▼               ▼               ▼               ▼         │
│   Store in         Use for       Proactive      Re-acquire      │
│   cache           requests       refresh        or delete       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Token Caching Strategy

### Cache Key Structure

Tokens are bound to the authenticated user:

```go
type TokenCacheKey struct {
    UserID         string // User identifier
    RouteID        string
    UpstreamServer string
}
```

### Cache Lookup Priority

1. Check in-memory cache (hot cache)
2. Fall back to databroker storage
3. Return nil if not found → trigger authorization

## Proactive Refresh

Refresh tokens **before** they expire to avoid request failures:

```
Token Lifetime: [────────────────────────────────────]
                                         ^
                                         │
                              Refresh window starts
                              (e.g., 5 minutes before expiry)
```

### Refresh Strategy

1. **Background Refresh**: Refresh in background when token enters refresh window
2. **Request-Time Refresh**: Block and refresh if token is in refresh window during request
3. **Concurrent Refresh Protection**: Ensure only one refresh occurs at a time per token

```go
const (
    RefreshWindowPercent = 0.1  // Refresh when 90% of lifetime elapsed
    MinRefreshWindow     = 5 * time.Minute
)

func shouldRefresh(token *UpstreamToken) bool {
    remaining := token.ExpiresAt.Sub(time.Now())
    lifetime := token.ExpiresAt.Sub(token.IssuedAt)

    window := max(
        time.Duration(float64(lifetime) * RefreshWindowPercent),
        MinRefreshWindow,
    )

    return remaining <= window
}
```

## Token Revocation

Tokens must be revoked in these scenarios:

| Event | Action |
|-------|--------|
| User logout | Delete all tokens for user |
| Policy change | Re-evaluate and potentially delete tokens |
| Route removal | Delete all tokens for route |
| Upstream access revoked | Delete tokens for upstream |
| Explicit user revocation | Delete specific tokens |

## Implementation Tasks

### Caching
- [ ] Implement in-memory cache with LRU eviction
- [ ] Implement cache population from databroker on miss
- [ ] Implement cache invalidation on token update
- [ ] Handle cache synchronization across Pomerium instances

### Token Lookup
- [ ] Implement `GetValidToken(key)` that returns only non-expired tokens
- [ ] Check refresh window and trigger refresh if needed
- [ ] Handle concurrent token lookups

### Proactive Refresh
- [ ] Implement refresh window calculation
- [ ] Implement background refresh worker
- [ ] Implement request-time blocking refresh
- [ ] Handle concurrent refresh requests (single-flight pattern)
- [ ] Handle refresh token rotation
- [ ] Handle refresh failures → mark token invalid

### Token Revocation
- [ ] Implement `RevokeTokensForUser(userID)`
- [ ] Implement `RevokeTokensForRoute(routeID)`
- [ ] Hook into user logout events
- [ ] Optional: Notify remote AS of revocation (if supported)

### Expiration Handling
- [ ] Implement background cleanup of expired tokens
- [ ] Remove tokens that failed refresh
- [ ] Handle tokens with no refresh token (must re-authorize on expiry)

## Acceptance Criteria

1. Valid tokens are returned from cache quickly
2. Tokens are refreshed before they expire
3. Refresh uses single-flight pattern to avoid duplicate requests
4. Tokens are revoked on user logout
5. Expired tokens are cleaned up automatically
6. Cache stays consistent across Pomerium instances
7. Audit log captures token lifecycle events

## References

- [MCP Proxy Epic](./index.md)
- [upstream-token-storage](./upstream-token-storage.md)

## Log

- 2026-01-26: Simplified to user-only token binding (removed per_session option)
- 2026-01-26: Issue created from epic breakdown
