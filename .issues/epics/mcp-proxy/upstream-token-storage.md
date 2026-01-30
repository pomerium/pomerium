---
id: upstream-token-storage
title: "Upstream Token Storage Record Type"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: high
labels:
  - mcp
  - proxy
  - storage
  - databroker
deps:
  - route-configuration-schema
---

# Upstream Token Storage Record Type

## Summary

Create a dedicated databroker record type for storing OAuth tokens acquired from remote MCP server authorization servers. This provides persistent, distributed storage for upstream tokens with proper lifecycle management.

## Requirements

From the epic (Open Questions):
> **Token Storage Backend**: Should upstream tokens use the existing session storage, or a dedicated token store with different lifecycle management?
>
> Answer: Existing databroker storage, just with some dedicated record type.

## Token Binding Keys

Tokens are bound to the authenticated user:

| Binding Mode | Primary Key | Description |
|-------------|-------------|-------------|
| `per_user` (default) | `(user_id, route_id, upstream_server)` | Shared across all sessions for same user |
| `service_account` | `(route_id, upstream_server)` | Single token for all requests (requires explicit config) |

## Record Schema

```protobuf
message UpstreamMCPToken {
  string id = 1;                           // Primary key
  string user_id = 2;                      // User identifier
  string route_id = 3;                     // Pomerium route identifier
  string upstream_server = 4;              // Remote MCP server URL

  string access_token = 5;                 // The access token
  string refresh_token = 6;                // The refresh token (if granted)
  string token_type = 7;                   // Token type (typically "Bearer")

  google.protobuf.Timestamp issued_at = 8;
  google.protobuf.Timestamp expires_at = 9;
  google.protobuf.Timestamp refresh_expires_at = 10;  // Optional

  repeated string scopes = 11;             // Granted scopes
  string audience = 12;                    // Token audience (resource indicator)

  // Discovery cache (to avoid re-fetching on every request)
  string authorization_server_issuer = 13;
  string token_endpoint = 14;
}
```

## Implementation Tasks

- [ ] Define protobuf message for `UpstreamMCPToken`
- [ ] Register record type with databroker
- [ ] Implement token storage operations:
  - [ ] `StoreToken(token)` - Store or update token
  - [ ] `GetToken(key)` - Retrieve token by binding key
  - [ ] `DeleteToken(key)` - Remove token
  - [ ] `DeleteTokensForUser(user_id)` - Bulk delete on user logout
  - [ ] `DeleteTokensForRoute(route_id)` - Bulk delete on route removal
- [ ] Implement token expiration checks
- [ ] Add encryption for token values at rest (if not already handled by databroker)
- [ ] Implement listing/querying for admin visibility

## Token Lifecycle Events

Storage operations should support these events:
1. **Acquisition**: Store new token after successful OAuth flow
2. **Refresh**: Update access token (and possibly refresh token) after refresh
3. **Revocation**: Delete token when user logs out or access is revoked
4. **Expiration**: Automatic cleanup of expired tokens

## Acceptance Criteria

1. Record type is registered and functional in databroker
2. Tokens can be stored, retrieved, and deleted by binding key
3. Bulk deletion works for user logout
4. Token values are encrypted at rest
5. Expired tokens are cleaned up automatically
6. Operations perform efficiently at scale

## Security Considerations

- Tokens MUST be encrypted at rest
- Access to token storage must be restricted
- Audit logging for token operations
- No logging of actual token values

## References

- [MCP Proxy Epic](./index.md)
- [Databroker Architecture](internal/databroker/)

## Log

- 2026-01-26: Simplified to user-only token binding (removed per_session option)
- 2026-01-26: Issue created from epic breakdown
