---
id: confused-deputy-mitigation
title: "Confused Deputy Attack Mitigation"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: high
labels:
  - mcp
  - security
deps:
  - token-audience-validation
---

# Confused Deputy Attack Mitigation

## Summary

Implement mitigations for confused deputy attacks when Pomerium acts as an MCP proxy server connecting to third-party APIs.

## Requirement (from MCP Specification)

> Attackers can exploit MCP servers acting as intermediaries to third-party APIs, leading to confused deputy vulnerabilities. By using stolen authorization codes, they can obtain access tokens without user consent.

> MCP proxy servers using static client IDs **MUST** obtain user consent for each dynamically registered client before forwarding to third-party authorization servers.

## Attack Scenario

When Pomerium MCP server proxies to third-party APIs:
1. User authenticates through Pomerium to access third-party API
2. Third-party authorization server sets consent cookie for Pomerium's static client ID
3. Attacker dynamically registers malicious MCP client with attacker's redirect_uri
4. Attacker sends victim crafted authorization link
5. Third-party AS sees existing consent cookie and skips consent screen
6. Authorization code is sent to attacker's redirect_uri
7. Attacker now has access as the victim

## Current State

The current implementation may be vulnerable to this attack when:
- Dynamic client registration is enabled
- Pomerium uses a static client ID with upstream authorization servers
- Consent cookies are set by upstream authorization servers

## Implementation Tasks

- [ ] Implement per-client consent storage (track approved client_ids per user)
- [ ] Show MCP server consent screen BEFORE initiating third-party authorization
- [ ] Display requesting client name/information clearly
- [ ] Show redirect_uri where tokens will be sent
- [ ] Implement CSRF protection for consent forms
- [ ] Use `frame-ancestors` CSP or X-Frame-Options: DENY
- [ ] Secure consent cookies with `__Host-` prefix and proper attributes
- [ ] Bind consent to specific client_id (not generic "user consented")
- [ ] Validate redirect URIs strictly (no open redirects)
- [ ] Add rate limiting on consent flows

## Consent UI Requirements

The MCP-level consent page **MUST**:
- Clearly identify the requesting MCP client by name
- Display the specific third-party API scopes being requested
- Show the registered `redirect_uri` where tokens will be sent
- Implement CSRF protection
- Prevent iframing

## Consent Cookie Security

If using cookies to track consent:
- Use `__Host-` prefix for cookie names
- Set `Secure`, `HttpOnly`, and `SameSite=Lax` attributes
- Cryptographically sign or use server-side sessions
- Bind to the specific `client_id`

## Acceptance Criteria

1. Per-client consent is required before third-party authorization
2. Consent UI clearly shows client information and redirect_uri
3. Consent state is securely stored per user/client combination
4. CSRF protection is implemented
5. Consent cookies are properly secured
6. Attack scenario from MCP spec is mitigated

## References

- [MCP Security Best Practices - Confused Deputy Problem](/.docs/mcp/basic/security_best_practices.mdx)
- [Wikipedia - Confused Deputy Problem](https://en.wikipedia.org/wiki/Confused_deputy_problem)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Verified not implemented - no per-client consent mechanism in current authorization flow
