---
id: token-audience-validation
title: "Token Audience Binding and Validation"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: critical
labels:
  - mcp
  - oauth2
  - security
deps:
  - resource-indicator-support
---

# Token Audience Binding and Validation

## Summary

Implement proper token audience validation to ensure MCP servers only accept tokens specifically issued for them, preventing token passthrough attacks and confused deputy vulnerabilities.

## Requirement (from MCP Specification)

> MCP servers **MUST** validate that access tokens were specifically issued for them as the intended audience, according to [RFC 8707 Section 2](/.docs/RFC/rfc8707.txt).

> MCP servers **MUST** only accept tokens specifically intended for themselves and **MUST** reject tokens that do not include them in the audience claim or otherwise verify that they are the intended recipient of the token.

> MCP servers **MUST NOT** accept or transit any other tokens.

## Security Context

This is critical for preventing:
1. **Token passthrough attacks** - Servers accepting tokens intended for other services
2. **Confused deputy problems** - Intermediate servers forwarding tokens inappropriately
3. **Privilege escalation** - Tokens being reused across trust boundaries

## Current State

The current implementation validates session tokens but may not properly enforce audience claims on access tokens according to RFC 8707.

## Implementation Tasks

- [ ] Include audience (`aud`) claim in issued access tokens bound to the resource
- [ ] Implement token validation that checks audience claim
- [ ] Reject tokens where audience doesn't match the current MCP server's resource identifier
- [ ] Add logging for rejected tokens (without exposing token contents)
- [ ] Ensure tokens are not forwarded to upstream services (no passthrough)
- [ ] Implement separate token acquisition for upstream API calls if needed
- [ ] Add configuration for strict vs. permissive audience validation modes

## Token Structure

Access tokens should include:
```json
{
  "aud": "https://mcp.example.com",  // Resource identifier
  "iss": "https://pomerium.example.com",
  "sub": "user-id",
  "exp": 1704067200,
  "scope": "openid offline"
}
```

## Acceptance Criteria

1. Access tokens include proper audience claims bound to the resource
2. Token validation rejects tokens with mismatched audience
3. No token passthrough to upstream services
4. Proper error responses (401 Unauthorized) for audience validation failures
5. Security logging for token validation events

## References

- [RFC 8707 - Resource Indicators for OAuth 2.0](/.docs/RFC/rfc8707.txt)
- [RFC 9068 - JSON Web Token Profile for OAuth 2.0 Access Tokens](/.docs/RFC/rfc9068.txt)
- [MCP Security Best Practices - Token Passthrough](/.docs/mcp/basic/security_best_practices.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
