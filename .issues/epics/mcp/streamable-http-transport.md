---
id: streamable-http-transport
title: "Streamable HTTP Transport Compliance"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: medium
labels:
  - mcp
  - protocol
  - sse
deps:
  - session-management
---

# Streamable HTTP Transport Compliance

## Summary

Ensure full compliance with the MCP Streamable HTTP transport specification, including SSE streaming, resumability, and proper content negotiation.

## Requirement (from MCP Specification)

The Streamable HTTP transport has specific requirements for:
1. POST requests for client-to-server messages
2. GET requests for server-to-client streams
3. SSE (Server-Sent Events) support
4. Resumability with event IDs
5. Proper content negotiation

## Current State

The current implementation provides basic HTTP endpoints but may not fully support:
- SSE streaming for long-running operations
- GET requests for server-initiated messages
- Resumability with `Last-Event-ID`
- Proper `Accept` header handling

## Implementation Tasks

### Content Negotiation
- [ ] Require `Accept` header with both `application/json` and `text/event-stream`
- [ ] Return appropriate content type based on response needs
- [ ] Support both JSON responses and SSE streams

### POST Request Handling
- [ ] Return HTTP 202 Accepted for notifications/responses
- [ ] Support SSE streaming for request responses
- [ ] Handle JSON-RPC error responses properly

### GET Request Handling
- [ ] Implement GET endpoint for server-to-client streams
- [ ] Return HTTP 405 if SSE not supported
- [ ] Support standalone SSE stream for server-initiated messages

### SSE Streaming
- [ ] Prime streams with initial event ID
- [ ] Support server-initiated connection closure for polling
- [ ] Include `retry` field before closing connections
- [ ] Send JSON-RPC requests/notifications on streams

### Resumability
- [ ] Assign unique event IDs to SSE events
- [ ] Encode stream identity in event IDs
- [ ] Handle `Last-Event-ID` header on GET requests
- [ ] Replay missed events on reconnection
- [ ] Track event history per stream

## Example SSE Stream

```
event: message
id: stream-abc123-ev001
data: {"jsonrpc":"2.0","method":"notifications/progress","params":{...}}

event: message
id: stream-abc123-ev002
data: {"jsonrpc":"2.0","id":1,"result":{...}}

```

## Acceptance Criteria

1. POST requests support both JSON and SSE responses
2. GET requests open SSE streams for server messages
3. Event IDs are globally unique within session
4. Resumption with Last-Event-ID works correctly
5. Connection closure and polling work as specified
6. Content negotiation is properly implemented

## References

- [MCP Transports - Streamable HTTP](/.docs/mcp/basic/transports.mdx)
- [SSE Specification](https://html.spec.whatwg.org/multipage/server-sent-events.html)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
