---
id: refresh-token-revocation
title: "Refresh Token Revocation Endpoint"
status: open
created: 2026-01-13
updated: 2026-01-13
priority: medium
labels:
  - mcp
  - oauth2
  - rfc7009
deps:
  - mcp-refresh-token-and-session-lifecycle
---

# Refresh Token Revocation Endpoint

## Summary

Implement revocation support for refresh tokens at the `/revoke` endpoint per RFC 7009.

## Requirement

From RFC 7009:
> Implementations **MUST** support the revocation of refresh tokens and SHOULD support the revocation of access tokens.

Refresh token revocation is a **MUST** requirement once refresh tokens are supported.

## Rationale

Refresh tokens are long-lived credentials that can be used to obtain new access tokens. Revocation is critical for:
- User sign-out (invalidate ability to get new tokens)
- Security incidents (compromised refresh token)
- Token rotation violations (detecting token theft)
- User-initiated session termination

## Current State

**BLOCKED.** Depends on `mcp-refresh-token-and-session-lifecycle` - refresh tokens must be implemented first.

Note: `handler_metadata.go` currently advertises `RevocationEndpoint` but no handler is registered. This should be removed until the endpoint is implemented.

## Implementation Tasks

- [ ] Create `/revoke` endpoint handler (or extend existing if access token revocation is done first)
- [ ] Parse revocation request body (`token`, `token_type_hint`)
- [ ] Implement client authentication (`client_secret_post`)
- [ ] For refresh tokens:
  - [ ] Mark refresh token as revoked in databroker
  - [ ] Revoke all access tokens in the same token family (rotation chain)
  - [ ] Consider revoking upstream IdP refresh token (see below)
- [ ] Return HTTP 200 for both valid and invalid token submissions
- [ ] Add route to mux router (if not already added by access token revocation)
- [ ] Advertise `RevocationEndpoint` in metadata once implemented
- [ ] Add unit and integration tests

## Request Format

```http
POST /mcp/revoke HTTP/1.1
Host: pomerium.example.com
Content-Type: application/x-www-form-urlencoded

token=<refresh_token>&token_type_hint=refresh_token
```

## Response

```http
HTTP/1.1 200 OK
Content-Type: application/json

{}
```

## Token Family Revocation

When a refresh token is revoked, all tokens in the same "family" (rotation chain) should be invalidated:

```
refresh_token_v1 → access_token_1
       ↓ (rotation)
refresh_token_v2 → access_token_2
       ↓ (rotation)
refresh_token_v3 → access_token_3  ← User revokes this
```

Revoking `refresh_token_v3` should also invalidate any previously issued tokens in the chain to prevent replay attacks.

## Upstream IdP Token Revocation

When revoking an MCP refresh token, consider also revoking the stored upstream IdP token:

| Scenario | Revoke Upstream? | Rationale |
|----------|------------------|-----------|
| User explicit logout | Yes | Complete sign-out |
| Token theft detected | Yes | Prevent further abuse |
| Token expiration | No | Normal lifecycle |
| Session cleanup | No | May affect other sessions |

Reference implementation in `internal/authenticateflow/stateful.go`:
```go
if err := authenticator.Revoke(ctx, manager.FromOAuthToken(sess.OauthToken)); err != nil {
    log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
}
```

Note: Not all IdPs support revocation. Check `provider.RevocationURL` before attempting.

## Acceptance Criteria

1. `/revoke` endpoint accepts POST requests with refresh tokens
2. Refresh tokens can be revoked via `token_type_hint=refresh_token`
3. Revoked refresh tokens cannot be used to obtain new access tokens
4. Token family is invalidated on revocation
5. HTTP 200 returned for all valid revocation requests
6. Client authentication is enforced
7. Optionally revokes upstream IdP token for explicit user logout

## References

- [RFC 7009 - OAuth 2.0 Token Revocation](/.docs/RFC/rfc7009.txt)
- [OAuth 2.1 Section 4.3.1 - Refresh Token Rotation](/.docs/RFC/draft-ietf-oauth-v2-1.txt)

## Log

- 2026-01-13: Issue created by splitting from `token-revocation`
