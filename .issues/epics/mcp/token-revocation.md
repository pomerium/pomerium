---
id: token-revocation
title: "Complete Token Revocation Implementation"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: medium
labels:
  - mcp
  - oauth2
deps:
  - refresh-token-support
---

# Complete Token Revocation Implementation

## Summary

Complete the token revocation endpoint implementation to properly revoke access tokens and refresh tokens.

## Requirement

The authorization server metadata advertises a revocation endpoint at `/revoke`, but the endpoint handler needs to be implemented.

From OAuth 2.1:
> The authorization server responds with HTTP status code 200 if the token has been revoked successfully or if the client submitted an invalid token.

## Current State

- `handler_metadata.go` advertises `RevocationEndpoint: P(path.Join(prefix, revocationEndpoint))`
- No revocation handler is implemented in `handler.go`
- Route is not registered in the mux router

## Implementation Tasks

- [ ] Create `/revoke` endpoint handler
- [ ] Parse revocation request (token, token_type_hint)
- [ ] Implement client authentication (client_secret_post as advertised)
- [ ] Revoke access tokens by marking them invalid
- [ ] Revoke refresh tokens and associated access tokens
- [ ] Implement token revocation storage in databroker
- [ ] Return HTTP 200 for both valid and invalid token submissions
- [ ] Handle revocation of token families (rotation)
- [ ] Add route to mux router

## Revocation Request

```http
POST /revoke HTTP/1.1
Host: pomerium.example.com
Content-Type: application/x-www-form-urlencoded

token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token
```

## Storage Considerations

For JWT access tokens:
- Maintain a revocation list or blacklist
- Check blacklist during token validation
- Consider token jti (JWT ID) for efficient lookups

For refresh tokens:
- Mark as revoked in databroker
- Revoke associated access tokens (token family)

## Upstream IdP Token Revocation

**Important Finding**: Current Pomerium session revocation behavior differs based on the trigger:

| Trigger | Session Deleted | Upstream Token Revoked |
|---------|-----------------|------------------------|
| User sign-out (`RevokeSession`) | ✅ Yes | ✅ Yes (via RFC 7009) |
| Session expiration (Identity Manager) | ✅ Yes | ❌ No |
| Refresh failure | ✅ Yes | ❌ No |

When implementing MCP token revocation, consider:

1. **MCP Refresh Token Revocation**: When an MCP refresh token is revoked, should we also revoke the stored upstream IdP refresh token?
   - **Pro**: Complete security - token can't be used anywhere
   - **Con**: May break other sessions using the same IdP token (if shared)

2. **Recommendation**: Call `authenticator.Revoke()` on the stored upstream refresh token when:
   - User explicitly revokes MCP token
   - Token theft is detected (rotation violation)

3. **Reference implementation** in `internal/authenticateflow/stateful.go`:
   ```go
   if err := authenticator.Revoke(ctx, manager.FromOAuthToken(sess.OauthToken)); err != nil {
       log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
   }
   ```

4. **IdP Support**: Not all IdPs support revocation endpoints. Check `provider.RevocationURL` before attempting. See `pkg/identity/oidc/oidc.go:277` for pattern.

## Acceptance Criteria

1. Revocation endpoint is registered and accessible
2. Access tokens can be revoked
3. Refresh tokens can be revoked
4. Revoked tokens are rejected on subsequent use
5. HTTP 200 is returned regardless of token validity
6. Client authentication is enforced

## References

- [RFC 7009 - OAuth 2.0 Token Revocation](/.docs/RFC/rfc7009.txt)
- [OAuth 2.1 Section 4.3.4](/.docs/RFC/draft-ietf-oauth-v2-1.txt)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
