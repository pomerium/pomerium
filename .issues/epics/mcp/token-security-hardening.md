---
id: token-security-hardening
title: "Token Storage and Transmission Security"
status: open
created: 2026-01-06
updated: 2026-01-06
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

## Requirement (from MCP Specification)

> Clients and servers **MUST** implement secure token storage and follow OAuth best practices, as outlined in OAuth 2.1, Section 7.1.

> Authorization servers **SHOULD** issue short-lived access tokens to reduce the impact of leaked tokens.

> For public clients, authorization servers **MUST** rotate refresh tokens as described in OAuth 2.1 Section 4.3.1.

## Current State

The current implementation stores tokens in the databroker and uses encrypted codes, but needs review against OAuth 2.1 security requirements.

## Implementation Tasks

### Token Lifetime
- [ ] Configure short-lived access token expiry (e.g., 1 hour default)
- [ ] Implement configurable token lifetime per client or scope
- [ ] Add refresh token expiry configuration
- [ ] Implement absolute session timeout

### Token Storage Security
- [ ] Review databroker token storage for security
- [ ] Encrypt tokens at rest if not already
- [ ] Implement secure deletion of expired tokens
- [ ] Add token lookup by user for revocation

### Transmission Security
- [ ] Ensure all token endpoints use HTTPS only
- [ ] Set proper response headers (Cache-Control, Pragma)
- [ ] Never include tokens in URLs (query strings)
- [ ] Validate Authorization header format

### Refresh Token Rotation
- [ ] Implement refresh token rotation for public clients
- [ ] Invalidate old refresh tokens on rotation
- [ ] Detect refresh token reuse (potential theft)
- [ ] Revoke token family on reuse detection

### Headers and Response Security
- [ ] Return `Cache-Control: no-store` on token responses
- [ ] Return `Pragma: no-cache` on token responses
- [ ] Set appropriate CORS headers
- [ ] Avoid leaking token info in error messages

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

1. Access tokens have configurable short lifetimes
2. Refresh token rotation is implemented for public clients
3. Token storage is encrypted and secure
4. All token responses include security headers
5. Refresh token reuse detection is implemented
6. Token cleanup runs for expired tokens

## References

- [OAuth 2.1 Section 7.1 - Token Security](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [OAuth 2.1 Section 4.3.1 - Refresh Token Rotation](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [MCP Authorization - Token Theft](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Verified partial implementation - token response headers (Cache-Control, Pragma) are set in handler_token.go:132-133, but refresh token rotation not implemented
