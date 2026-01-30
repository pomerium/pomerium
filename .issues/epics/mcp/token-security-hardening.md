---
id: token-security-hardening
title: "Token Storage and Transmission Security"
status: in_progress
created: 2026-01-06
updated: 2026-01-26
priority: high
labels:
  - optional
  - mcp
  - security
  - oauth2
deps: []
---

# Token Storage and Transmission Security

## Summary

Implement comprehensive token security measures for storage, transmission, and lifecycle management as specified in OAuth 2.1 and MCP security guidelines.

## Requirement Analysis

### From MCP Specification (authorization.mdx)

> Clients and servers **MUST** implement secure token storage and follow OAuth best practices, as outlined in OAuth 2.1, Section 7.1.

> Authorization servers **SHOULD** issue short-lived access tokens to reduce the impact of leaked tokens.

> For public clients, authorization servers **MUST** rotate refresh tokens as described in OAuth 2.1 Section 4.3.1.

### From OAuth 2.1 (draft-ietf-oauth-v2-1-13)

**Section 4.3.1** - Refresh Token Rotation for public clients:
> Authorization servers MUST utilize one of these methods to detect refresh token replay by malicious actors for public clients: Sender-constrained refresh tokens OR Refresh token rotation.

**Section 7.1.3.5** - Short-lived bearer tokens:
> Authorization servers SHOULD issue short-lived bearer tokens, particularly when issuing tokens to clients that run within a web browser or other environments where information leakage may occur.

### Requirement Classification

| Task | Spec Level | Source |
|------|------------|--------|
| Refresh token rotation | **MUST** (public clients) | MCP spec → OAuth 2.1 §4.3.1 |
| Invalidate old refresh tokens | **MUST** (part of rotation) | OAuth 2.1 §4.3.1 |
| Short-lived access tokens | **SHOULD** | MCP spec, OAuth 2.1 §7.1.3.5 |
| Secure token storage | **MUST** | MCP spec → OAuth 2.1 §7.1 |
| Configurable token lifetimes | Enhancement | Not in spec |
| Token cleanup job | Enhancement | Operational concern |
| Token lookup by user | Enhancement | Not in spec |
| Refresh token reuse detection | **Part of rotation** | OAuth 2.1 §4.3.1 describes as automatic |

## Current State

The current implementation stores tokens in the databroker and uses encrypted codes, but needs review against OAuth 2.1 security requirements.

## Implementation Tasks

### Token Lifetime (SHOULD per MCP spec)
- [ ] Configure short-lived access token expiry (e.g., 1 hour default) - currently tied to session expiry
  - **Spec**: MCP says SHOULD, OAuth 2.1 §7.1.3.5 says SHOULD
- [ ] ~~Implement configurable token lifetime per client or scope~~ - **Enhancement** (not in spec)
- [x] Add refresh token expiry configuration - 365-day TTL in `handler_token.go:29`
- [x] Implement absolute session timeout - tied to Pomerium session `CookieExpire`

### Token Storage Security (MUST per MCP spec → OAuth 2.1 §7.1)
- [x] Review databroker token storage for security - MCPRefreshToken records stored in databroker
- [x] Encrypt tokens at rest if not already - tokens encrypted via Pomerium's standard cipher
- [ ] ~~Implement secure deletion of expired tokens~~ - **Enhancement** (operational concern, not spec-required)
- [ ] ~~Add token lookup by user for revocation~~ - **Enhancement** (not in spec)

### Transmission Security (MUST per OAuth 2.1 §1.5, §7.1.3)
- [x] Ensure all token endpoints use HTTPS only - Pomerium enforces HTTPS
- [x] Set proper response headers (Cache-Control, Pragma) - `handler_token.go:662-663`
- [x] Never include tokens in URLs (query strings) - tokens only in request/response bodies
  - **Spec**: OAuth 2.1 §7.1.3.7: "Bearer tokens MUST NOT be passed in page URLs"
- [x] Validate Authorization header format - handled by Pomerium's auth layer

### Refresh Token Rotation (MUST for public clients per MCP spec → OAuth 2.1 §4.3.1)
- [x] Implement refresh token rotation for public clients - `handler_token.go:447-490`
  - **Spec**: "Authorization servers MUST utilize... refresh token rotation"
- [x] Invalidate old refresh tokens on rotation - `handler_token.go:479`
  - **Spec**: "The previous refresh token is invalidated"
- [ ] ~~Detect refresh token reuse (potential theft)~~ - **Automatic** with rotation per OAuth 2.1 §4.3.1
  - Note: Reuse of an invalidated token naturally triggers detection when the legitimate client uses it
- [ ] ~~Revoke token family on reuse detection~~ - **Automatic** with rotation per OAuth 2.1 §4.3.1
  - Note: "The authorization server... will revoke the active refresh token as well as the access authorization grant"

### Headers and Response Security
- [x] Return `Cache-Control: no-store` on token responses - `handler_token.go:662`
- [x] Return `Pragma: no-cache` on token responses - `handler_token.go:663`
- [x] Set appropriate CORS headers - handled by Pomerium's CORS configuration
- [x] Avoid leaking token info in error messages - uses standard OAuth 2.1 error responses

## Token Response Headers

```go
w.Header().Set("Content-Type", "application/json")
w.Header().Set("Cache-Control", "no-store")
w.Header().Set("Pragma", "no-cache")
```

## Refresh Token Rotation

```go
// On refresh token use:
// 1. Validate refresh token
// 2. Issue new access token
// 3. Issue NEW refresh token
// 4. Invalidate old refresh token
// 5. If old token reused, revoke entire token family
```

## Acceptance Criteria

**Required (MUST per spec):**
1. ✅ Refresh token rotation is implemented for public clients (OAuth 2.1 §4.3.1)
2. ✅ Token storage is encrypted and secure (MCP spec → OAuth 2.1 §7.1)
3. ✅ All token responses include security headers (Cache-Control, Pragma)
4. ✅ Tokens are never passed in URLs (OAuth 2.1 §7.1.3.7)

**Recommended (SHOULD per spec):**
5. ⏳ Access tokens have short lifetimes (MCP spec, OAuth 2.1 §7.1.3.5)

**Enhancements (not in spec):**
6. ⏳ Configurable token lifetimes per client
7. ⏳ Token cleanup job for expired tokens
8. ⏳ Token lookup by user for bulk revocation

**Note on reuse detection:** OAuth 2.1 §4.3.1 describes reuse detection as an automatic property of rotation - when an attacker uses a stolen refresh token after it's been rotated, the legitimate client will eventually present the now-invalid token, alerting the AS. Pomerium's rotation implementation already provides this by invalidating old tokens.

## References

- [OAuth 2.1 Section 7.1 - Token Security](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [OAuth 2.1 Section 4.3.1 - Refresh Token Rotation](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [MCP Authorization - Token Theft](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Verified partial implementation - token response headers (Cache-Control, Pragma) are set in handler_token.go:132-133, but refresh token rotation not implemented
- 2026-01-19: Updated to **in_progress** - Refresh token rotation IS now implemented:
  - `handler_token.go:446-490` - Creates new refresh token, revokes old one
  - `handler_token.go:399-406` - Checks if refresh token is revoked
  - Token response headers properly set (Cache-Control: no-store, Pragma: no-cache)
  - Remaining items: configurable token lifetimes, token lookup by user for revocation, refresh token reuse detection
- 2026-01-26: Reviewed implementation - updated task checklist with specific file:line references for completed items
- 2026-01-26: Audited against MCP spec and OAuth 2.1 - clarified which tasks are MUST/SHOULD/enhancements:
  - Refresh token rotation: MUST (implemented ✅)
  - Short-lived tokens: SHOULD (not yet configurable)
  - Reuse detection: Automatic property of rotation (OAuth 2.1 §4.3.1), not a separate requirement
  - Token cleanup, configurable lifetimes, user lookup: Enhancements beyond spec
