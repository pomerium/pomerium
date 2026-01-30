---
id: streamable-http-transport
title: "Streamable HTTP Transport Compliance"
status: cancelled
created: 2026-01-06
updated: 2026-01-26
priority: low
labels:
  - not-applicable
  - mcp
  - protocol
  - sse
---

# Streamable HTTP Transport Compliance

## Summary

~~Ensure full compliance with the MCP Streamable HTTP transport specification, including SSE streaming, resumability, and proper content negotiation.~~

**Cancelled**: Not applicable for gateway implementations. These requirements are for MCP servers/clients to implement, not gateways.

## Requirement (from MCP Specification)

The Streamable HTTP transport has specific requirements for:
1. POST requests for client-to-server messages
2. GET requests for server-to-client streams
3. SSE (Server-Sent Events) support
4. Resumability with event IDs
5. Proper content negotiation
6. Session management via `MCP-Session-Id` header
7. Protocol version via `MCP-Protocol-Version` header

## Analysis: Why This Is Not Applicable for Gateways

As a gateway/proxy, Pomerium does not need to implement any of these requirements because:

### Standard HTTP Proxying Handles Everything

| Requirement | Gateway Behavior |
|-------------|------------------|
| POST/GET requests | Standard HTTP proxy - passes through |
| SSE streaming | Envoy handles natively via HTTP/1.1 or HTTP/2 |
| `MCP-Session-Id` header | Passed through as any HTTP header |
| `Last-Event-ID` header | Passed through as any HTTP header |
| `MCP-Protocol-Version` header | Passed through as any HTTP header |
| Content negotiation | Passed through, no special handling needed |

### Existing Timeout Configuration

Per-route timeout configuration is already available for users who need to configure long-lived SSE streams:

- `timeout` - upstream route timeout (default 30s, set to `0s` for indefinite)
- `idle_timeout` - connection idle timeout (configurable per-route)

See `config/envoyconfig/routes.go:588-609` for implementation.

### User Configuration Example

For MCP servers with long-running SSE streams, users can configure:

```yaml
- from: https://mcp-server.example.com
  to: https://upstream-mcp-server:8080
  mcp:
    server: {}
  timeout: 0s        # Disable route timeout for long-lived SSE streams
  idle_timeout: 10m  # Adjust as needed
```

## References

- [MCP Transports - Streamable HTTP](/.docs/mcp/basic/transports.mdx)
- [SSE Specification](https://html.spec.whatwg.org/multipage/server-sent-events.html)
- MCP Spec Changes:
  - [SEP-1699](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1699) - Support polling SSE streams
  - [Issue #1847](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1847) - GET streams clarification

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Verified not implemented - no SSE streaming, no GET endpoint for server-to-client streams, no resumability support
- 2026-01-26: Cancelled - not applicable for gateway implementations. Pomerium's standard HTTP proxying already handles all transport-layer requirements transparently. SSE streaming works out of the box via Envoy, and all MCP-specific headers pass through naturally.
