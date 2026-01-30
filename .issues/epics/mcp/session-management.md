---
id: session-management
title: "MCP Session Management (MCP-Session-Id)"
status: open
created: 2026-01-06
updated: 2026-01-26
priority: high
labels:
  - mcp
  - protocol
  - envoy
deps: []
---

# MCP Session Management (MCP-Session-Id)

## Summary

Implement MCP session management using the `MCP-Session-Id` header for stateful Streamable HTTP transport sessions, including sticky routing to ensure requests with the same session are routed to the same upstream server.

## Important: MCP Sessions vs Pomerium Sessions

**MCP sessions are NOT the same as Pomerium authentication sessions.** They serve different purposes:

| Aspect | MCP Session | Pomerium Session |
|--------|-------------|------------------|
| Purpose | Protocol-level stateful parameter for correlating MCP messages | Authentication state and user identity |
| Header | `MCP-Session-Id` | Pomerium cookie |
| Scope | Single MCP client-server conversation | User's authenticated browser session |
| Lifecycle | Created at MCP `initialize`, ends with DELETE or timeout | Login to logout/expiration |
| Storage | Upstream MCP server (stateful) | Pomerium databroker |

An MCP session represents a **stateful conversation** between an MCP client and server. The upstream MCP server maintains state associated with this session (tools, resources, prompts, conversation context). This is why sticky routing is essential.

## Requirement (from MCP Specification)

> A server using the Streamable HTTP transport **MAY** assign a session ID at initialization time, by including it in an `MCP-Session-Id` header on the HTTP response containing the `InitializeResult`.
>
> - The session ID **SHOULD** be globally unique and cryptographically secure (e.g., a securely generated UUID, a JWT, or a cryptographic hash).
> - The session ID **MUST** only contain visible ASCII characters (ranging from 0x21 to 0x7E).
> - The client **MUST** handle the session ID in a secure manner.

> If an `MCP-Session-Id` is returned by the server during initialization, clients using the Streamable HTTP transport **MUST** include it in the `MCP-Session-Id` header on all of their subsequent HTTP requests.

## Current State

The current MCP handler does not implement MCP session ID management. The upstream MCP server generates and manages its own `MCP-Session-Id`, but Pomerium does not leverage this for routing decisions.

## Implementation Tasks

### Sticky Routing (Required for Stateful MCP Servers)

When multiple upstream MCP servers exist, requests with the same `MCP-Session-Id` must route to the same upstream to maintain session state.

- [ ] Extract `MCP-Session-Id` header from incoming requests
- [ ] Generate routing key from MCP-Session-Id using deterministic hash (SHA256)
- [ ] Add `x-pomerium-routing-key` header for Envoy consistent hashing
- [ ] Configure RING_HASH or MAGLEV load balancing for MCP routes
- [ ] Handle initial request (no MCP-Session-Id yet) - use fallback routing

### Routing Key Flow

```
MCP Client Request
        ↓
   Has MCP-Session-Id header?
        ↓
   Yes → Generate x-pomerium-routing-key = SHA256(MCP-Session-Id)
        ↓
   Envoy uses HashPolicy with RING_HASH/MAGLEV
        ↓
   Route to consistent upstream based on hash
```

### Reference: Existing Pomerium Sticky Routing

Pomerium already implements sticky routing for authenticated sessions:

- **Routing key generation:** `authorize/evaluator/headers_evaluator_evaluation.go:171-180`
  ```go
  if policy.LoadBalancingPolicy == RING_HASH || MAGLEV {
      headers.Add("x-pomerium-routing-key", cryptoSHA256(session.ID))
  }
  ```

- **Envoy HashPolicy:** `config/envoyconfig/routes.go:476-495`
  ```go
  HashPolicy: []*RouteAction_HashPolicy{
      {Header: {HeaderName: "x-pomerium-routing-key"}, Terminal: true},
      {ConnectionProperties: {SourceIp: true}, Terminal: true}, // fallback
  }
  ```

For MCP, we need similar logic but keyed on `MCP-Session-Id` instead of Pomerium session ID.

### Optional: Session Header Validation

These tasks are optional if the upstream MCP server handles session validation:

- [ ] Validate `MCP-Session-Id` header format (visible ASCII 0x21-0x7E)
- [ ] Return HTTP 400 Bad Request for malformed session IDs
- [ ] Pass through HTTP 404 from upstream for expired/invalid sessions

## Implementation Options

### Option 1: MCP Handler Integration (Recommended)

Add MCP-Session-Id extraction and routing key generation in the MCP handler:

```go
// In MCP handler, extract session ID and set routing key
func (h *Handler) setRoutingKey(r *http.Request) {
    mcpSessionID := r.Header.Get("MCP-Session-Id")
    if mcpSessionID != "" {
        routingKey := cryptoSHA256(mcpSessionID)
        r.Header.Set("x-pomerium-routing-key", routingKey)
    }
}
```

### Option 2: Authorize Evaluator Extension

Extend the existing headers evaluator to handle MCP-Session-Id:

```go
// In headers_evaluator_evaluation.go
func (e *headersEvaluatorEvaluation) fillRoutingKeyHeaders() {
    // Existing pomerium session routing
    if usesConsistentHashing(policy) && e.request.Session.ID != "" {
        e.response.Headers.Add("x-pomerium-routing-key", cryptoSHA256(e.request.Session.ID))
        return
    }

    // MCP session routing fallback
    mcpSessionID := e.request.HTTP.Headers.Get("MCP-Session-Id")
    if usesConsistentHashing(policy) && mcpSessionID != "" {
        e.response.Headers.Add("x-pomerium-routing-key", cryptoSHA256(mcpSessionID))
    }
}
```

## Acceptance Criteria

1. Requests with the same `MCP-Session-Id` are routed to the same upstream server
2. Routing is deterministic based on hash of MCP-Session-Id
3. Initial requests (no MCP-Session-Id) fall back to source IP or round-robin
4. Works with RING_HASH and MAGLEV load balancing policies
5. Does not interfere with Pomerium session-based routing (pomerium session takes precedence)

## Out of Scope

The following are handled by the upstream MCP server, not Pomerium:

- Generating MCP-Session-Id values
- Storing MCP session state
- Session expiration and cleanup
- HTTP DELETE session termination
- Returning 404 for invalid sessions

Pomerium's role is to **route** MCP requests consistently, not to **manage** MCP session state.

## References

- [MCP Transports - Session Management](/.docs/mcp/basic/transports.mdx)
- [MCP Security Best Practices - Session Hijacking](/.docs/mcp/basic/security_best_practices.mdx)
- [Pomerium Sticky Routing](authorize/evaluator/headers_evaluator_evaluation.go)
- [Envoy HashPolicy Configuration](config/envoyconfig/routes.go)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Verified not implemented - no MCP-Session-Id header handling in handler.go
- 2026-01-26: Clarified MCP vs Pomerium sessions; refocused on sticky routing requirement
