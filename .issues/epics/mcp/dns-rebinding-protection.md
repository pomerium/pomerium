---
id: dns-rebinding-protection
title: "DNS Rebinding Attack Protection"
status: cancelled
created: 2026-01-06
updated: 2026-01-13
priority: low
labels:
  - optional
  - mcp
  - security
deps: []
---

# DNS Rebinding Attack Protection

## Status: CANCELLED

**This ticket is not applicable to Pomerium's architecture.** See [Why Not Applicable](#why-not-applicable-to-pomerium) below.

---

## Summary

Implement DNS rebinding attack protection for the Streamable HTTP transport by validating Origin headers on all incoming connections.

## Requirement (from MCP Specification)

> **Security Warning** - When implementing Streamable HTTP transport:
>
> 1. Servers **MUST** validate the `Origin` header on all incoming connections to prevent DNS rebinding attacks
>    - If the `Origin` header is present and invalid, servers **MUST** respond with HTTP 403 Forbidden
> 2. When running locally, servers **SHOULD** bind only to localhost (127.0.0.1) rather than all network interfaces (0.0.0.0)
> 3. Servers **SHOULD** implement proper authentication for all connections

---

## Why Not Applicable to Pomerium

### MCP Spec's Target Threat Model

The MCP specification's DNS rebinding requirement targets **local MCP servers running without authentication**:

```
Attacker's website JS
        ↓ (DNS rebinding to localhost)
Local MCP server (no auth, listening on 127.0.0.1:3000)
        ↓
Executes MCP commands as local user
```

This is a real threat for standalone MCP servers that:
- Run on localhost without authentication
- Accept any request regardless of Origin
- Have no other security controls

### Pomerium's Architecture

Pomerium operates as an **authenticated gateway** with a fundamentally different architecture:

```
Attacker's website JS
        ↓
Pomerium (requires authentication)
        ↓ (blocked without valid session)
Upstream MCP server (not directly accessible)
```

**Key protections already in place:**

| Layer | Protection |
|-------|------------|
| **Authentication** | All requests require valid Pomerium session |
| **OAuth endpoints** | Protected by PKCE, state parameter, redirect URI validation |
| **Session cookies** | HttpOnly, SameSite attributes prevent JS access |
| **Network isolation** | Upstream MCP servers not directly exposed to internet |

### Why `AllowedOrigins: ["*"]` is Acceptable

The current CORS configuration allows any origin, but this doesn't create a vulnerability because:

1. **OAuth endpoints** (`/mcp/authorize`, `/mcp/token`, `/mcp/register`):
   - PKCE prevents authorization code interception
   - State parameter prevents CSRF
   - Redirect URI validation prevents token theft
   - These are standard OAuth protections, not reliant on Origin

2. **Session-based endpoints** (`/mcp/connect`, `/mcp/list-routes`):
   - Require authenticated Pomerium session
   - Session cookies are HttpOnly (not accessible to attacker's JS)
   - Session cookies have SameSite attribute

3. **Upstream MCP servers**:
   - Not directly accessible from the internet
   - All traffic goes through Pomerium's authenticated proxy

### Conclusion

The MCP spec's DNS rebinding requirement assumes a threat model (unauthenticated local server) that doesn't apply to Pomerium. Pomerium's authentication layer provides equivalent or better protection.

**Implementing strict Origin validation would add complexity without meaningful security benefit.**

---

## Original Analysis (for reference)

### Attack Vector

DNS rebinding attacks allow malicious websites to bypass same-origin policy by:
1. Hosting malicious JavaScript on attacker's domain
2. Making DNS record for attacker's domain initially resolve to attacker's IP
3. After page loads, changing DNS to resolve to victim's local IP (e.g., 127.0.0.1)
4. Making requests that browser sends to local MCP server with attacker's Origin

Without Origin validation, the local MCP server would accept these requests.

### Current Implementation

The current implementation uses CORS middleware with `AllowedOrigins: []string{"*"}`:

- `internal/mcp/handler.go:108-112`
- `internal/mcp/handler_metadata.go:189-193`

This is acceptable for Pomerium's architecture as explained above.

## References

- [MCP Transports - Security Warning](/.docs/mcp/basic/transports.mdx)
- [DNS Rebinding Attack Description](https://en.wikipedia.org/wiki/DNS_rebinding)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis - marked critical for security
- 2026-01-13: Verified current state - AllowedOrigins: "*" is used in both handler.go and handler_metadata.go
- 2026-01-13: Status changed to **cancelled** - not applicable to Pomerium's architecture (authenticated gateway with OAuth protections)
