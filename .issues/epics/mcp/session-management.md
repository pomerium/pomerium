---
id: session-management
title: "MCP Session Management (MCP-Session-Id)"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: high
labels:
  - mcp
  - protocol
deps: []
---

# MCP Session Management (MCP-Session-Id)

## Summary

Implement MCP session management using the `MCP-Session-Id` header for stateful Streamable HTTP transport sessions.

## Requirement (from MCP Specification)

> A server using the Streamable HTTP transport **MAY** assign a session ID at initialization time, by including it in an `MCP-Session-Id` header on the HTTP response containing the `InitializeResult`.
>
> - The session ID **SHOULD** be globally unique and cryptographically secure (e.g., a securely generated UUID, a JWT, or a cryptographic hash).
> - The session ID **MUST** only contain visible ASCII characters (ranging from 0x21 to 0x7E).
> - The client **MUST** handle the session ID in a secure manner.

> If an `MCP-Session-Id` is returned by the server during initialization, clients using the Streamable HTTP transport **MUST** include it in the `MCP-Session-Id` header on all of their subsequent HTTP requests.

## Current State

The current MCP handler does not implement session ID management. Session state is managed through Pomerium's existing session infrastructure but not exposed via MCP-Session-Id header.

## Implementation Tasks

- [ ] Generate cryptographically secure session IDs during initialization
- [ ] Include `MCP-Session-Id` header in InitializeResult response
- [ ] Validate `MCP-Session-Id` header on subsequent requests
- [ ] Return HTTP 400 Bad Request for requests missing required session ID
- [ ] Return HTTP 404 Not Found for expired/invalid session IDs
- [ ] Implement session expiration and cleanup
- [ ] Support HTTP DELETE for explicit session termination
- [ ] Add session state storage in databroker
- [ ] Ensure session IDs use only visible ASCII characters (0x21-0x7E)

## Session ID Format Options

1. **UUID v4**: Simple, widely supported
   ```
   MCP-Session-Id: 550e8400-e29b-41d4-a716-446655440000
   ```

2. **JWT**: Self-contained with claims
   ```
   MCP-Session-Id: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

3. **Cryptographic Hash**: Derived from session parameters
   ```
   MCP-Session-Id: sha256:a1b2c3d4e5f6...
   ```

## Acceptance Criteria

1. Session IDs are generated and returned in InitializeResult responses
2. Subsequent requests are validated against the session ID
3. Missing session ID returns HTTP 400
4. Invalid/expired session ID returns HTTP 404
5. HTTP DELETE terminates the session
6. Session state persists across requests
7. Session IDs meet security requirements (cryptographically secure, ASCII only)

## References

- [MCP Transports - Session Management](/.docs/mcp/basic/transports.mdx)
- [MCP Security Best Practices - Session Hijacking](/.docs/mcp/basic/security_best_practices.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
