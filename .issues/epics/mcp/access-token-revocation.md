---
id: access-token-revocation
title: "Access Token Revocation Endpoint"
status: open
created: 2026-01-13
updated: 2026-01-13
priority: low
labels:
  - optional
  - mcp
  - oauth2
  - rfc7009
deps: []
---

# Access Token Revocation Endpoint

## Summary

Implement revocation support for access tokens at the `/revoke` endpoint per RFC 7009.

## Requirement

From RFC 7009:
> Implementations MUST support the revocation of refresh tokens and **SHOULD** support the revocation of access tokens.

Access token revocation is a **SHOULD** (recommended but not required).

## Rationale

Access tokens in the current implementation are short-lived session-bound tokens. Revocation is less critical than for refresh tokens since:
- Access tokens expire relatively quickly
- Without refresh tokens, the user must re-authenticate anyway

However, revocation is still useful for:
- Immediate logout scenarios
- Security incidents where tokens may be compromised
- Compliance with OAuth best practices

## Current State

**NOT IMPLEMENTED.** The `/revoke` endpoint does not exist.

Note: `handler_metadata.go` currently advertises `RevocationEndpoint` but no handler is registered. This should be removed until the endpoint is implemented (see Implementation Tasks).

## Implementation Tasks

- [ ] Remove `RevocationEndpoint` from metadata until implemented
- [ ] Create `/revoke` endpoint handler (`handler_revoke.go`)
- [ ] Parse revocation request body (`token`, `token_type_hint`)
- [ ] Implement client authentication (`client_secret_post` as will be advertised)
- [ ] For access tokens: invalidate the underlying session or add to a revocation list
- [ ] Return HTTP 200 for both valid and invalid token submissions (per RFC 7009)
- [ ] Add route to mux router in `handler.go`
- [ ] Add `RevocationEndpoint` back to metadata once implemented
- [ ] Add unit tests

## Request Format

```http
POST /mcp/revoke HTTP/1.1
Host: pomerium.example.com
Content-Type: application/x-www-form-urlencoded

token=<access_token>&token_type_hint=access_token
```

## Response

Per RFC 7009, the server MUST return HTTP 200 regardless of whether the token was valid, already revoked, or unknown. This prevents token probing attacks.

```http
HTTP/1.1 200 OK
Content-Type: application/json

{}
```

## Storage Considerations

Current access tokens are encrypted session references. To revoke:
1. Decrypt the token to get the session ID
2. Delete or mark the session as revoked in databroker
3. Subsequent requests with that token will fail validation

## Acceptance Criteria

1. `/revoke` endpoint accepts POST requests
2. Access tokens can be revoked via `token_type_hint=access_token`
3. Revoked access tokens are rejected on subsequent use
4. HTTP 200 returned for all valid revocation requests (even for invalid tokens)
5. Client authentication is enforced

## References

- [RFC 7009 - OAuth 2.0 Token Revocation](/.docs/RFC/rfc7009.txt)

## Log

- 2026-01-13: Issue created by splitting from `token-revocation`
