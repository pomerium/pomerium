---
id: token-introspection
title: "Implement Token Introspection Endpoint (RFC 7662)"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: medium
labels:
  - mcp
  - oauth2
  - rfc7662
deps: []
---

# Implement Token Introspection Endpoint (RFC 7662)

## Summary

Implement OAuth 2.0 Token Introspection endpoint as defined in RFC 7662 to allow resource servers to query the authorization server about access token state.

## Requirement

The authorization server metadata advertises `introspection_endpoint` as an optional field. While not strictly required by MCP, token introspection provides valuable functionality for:
- Validating opaque access tokens
- Checking token revocation status
- Obtaining token metadata (scope, expiry, subject)

## Current State

- `handler_metadata.go` has `IntrospectionEndpoint` field but it's not populated
- No introspection endpoint handler is implemented
- Access tokens are currently self-validating (JWT format)

## Implementation Tasks

- [ ] Create `/introspect` endpoint handler
- [ ] Implement token parsing and validation
- [ ] Return active/inactive status
- [ ] Include token metadata in response (scope, exp, sub, iat, etc.)
- [ ] Implement client authentication for introspection requests
- [ ] Add rate limiting to prevent token enumeration
- [ ] Update authorization server metadata with endpoint
- [ ] Handle both access tokens and refresh tokens
- [ ] Add proper error responses for invalid requests

## Introspection Response

```json
{
  "active": true,
  "scope": "openid offline",
  "client_id": "s6BhdRkqt3",
  "username": "jdoe",
  "token_type": "Bearer",
  "exp": 1419356238,
  "iat": 1419350238,
  "sub": "Z5O3upPC88QrAjx00dis",
  "aud": "https://mcp.example.com",
  "iss": "https://pomerium.example.com"
}
```

## Acceptance Criteria

1. Introspection endpoint accepts POST requests with token parameter
2. Valid tokens return `active: true` with metadata
3. Invalid/expired tokens return `active: false`
4. Client authentication is enforced
5. Rate limiting prevents enumeration attacks
6. Authorization server metadata includes endpoint

## References

- [RFC 7662 - OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
