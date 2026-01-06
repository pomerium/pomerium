---
id: dns-rebinding-protection
title: "DNS Rebinding Attack Protection"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: critical
labels:
  - mcp
  - security
  - critical
deps: []
---

# DNS Rebinding Attack Protection

## Summary

Implement DNS rebinding attack protection for the Streamable HTTP transport by validating Origin headers on all incoming connections.

## Requirement (from MCP Specification)

> **Security Warning** - When implementing Streamable HTTP transport:
>
> 1. Servers **MUST** validate the `Origin` header on all incoming connections to prevent DNS rebinding attacks
>    - If the `Origin` header is present and invalid, servers **MUST** respond with HTTP 403 Forbidden
> 2. When running locally, servers **SHOULD** bind only to localhost (127.0.0.1) rather than all network interfaces (0.0.0.0)
> 3. Servers **SHOULD** implement proper authentication for all connections

## Attack Vector

DNS rebinding attacks allow malicious websites to bypass same-origin policy by:
1. Hosting malicious JavaScript on attacker's domain
2. Making DNS record for attacker's domain initially resolve to attacker's IP
3. After page loads, changing DNS to resolve to victim's local IP (e.g., 127.0.0.1)
4. Making requests that browser sends to local MCP server with attacker's Origin

Without Origin validation, the local MCP server would accept these requests.

## Current State

The current implementation uses CORS middleware but may not enforce strict Origin validation that would block DNS rebinding attacks.

From `handler.go`:
```go
r.Use(cors.New(cors.Options{
    AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
    AllowedOrigins: []string{"*"},  // Too permissive!
    AllowedHeaders: []string{"content-type", "mcp-protocol-version"},
}).Handler)
```

## Implementation Tasks

- [ ] Remove wildcard `*` from AllowedOrigins
- [ ] Implement Origin header validation middleware
- [ ] Configure allowed origins based on deployment configuration
- [ ] Return HTTP 403 Forbidden for invalid Origins (with optional JSON-RPC error body)
- [ ] Add localhost binding configuration for local deployments
- [ ] Log Origin validation failures for security monitoring
- [ ] Add configuration option for strict vs. permissive modes
- [ ] Document security implications in deployment guide

## Example Validation Logic

```go
func validateOrigin(origin string, allowedOrigins []string) bool {
    if origin == "" {
        // Requests without Origin may be allowed in some cases
        return true
    }
    for _, allowed := range allowedOrigins {
        if origin == allowed {
            return true
        }
    }
    return false
}
```

## Acceptance Criteria

1. Origin header is validated on all MCP endpoint requests
2. Invalid Origins receive HTTP 403 Forbidden response
3. Allowed origins are configurable per deployment
4. Local deployments bind to localhost by default
5. Security logging captures Origin validation events
6. Documentation covers DNS rebinding risks and configuration

## References

- [MCP Transports - Security Warning](/.docs/mcp/basic/transports.mdx)
- [DNS Rebinding Attack Description](https://en.wikipedia.org/wiki/DNS_rebinding)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis - marked critical for security
