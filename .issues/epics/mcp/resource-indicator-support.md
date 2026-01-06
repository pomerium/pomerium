---
id: resource-indicator-support
title: "Implement RFC 8707 Resource Indicators"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: high
labels:
  - mcp
  - oauth2
  - rfc8707
deps: []
---

# Implement RFC 8707 Resource Indicators

## Summary

Implement Resource Indicators for OAuth 2.0 as defined in RFC 8707 to explicitly specify the target MCP server for which tokens are being requested.

## Requirement (from MCP Specification)

> MCP clients **MUST** implement Resource Indicators for OAuth 2.0 as defined in [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) to explicitly specify the target resource for which the token is being requested. The `resource` parameter:
>
> 1. **MUST** be included in both authorization requests and token requests.
> 2. **MUST** identify the MCP server that the client intends to use the token with.
> 3. **MUST** use the canonical URI of the MCP server as defined in RFC 8707 Section 2.

## Current State

The current implementation does not process or validate the `resource` parameter in authorization or token requests.

## Implementation Tasks

- [ ] Parse `resource` parameter from authorization requests
- [ ] Parse `resource` parameter from token requests
- [ ] Validate that `resource` matches the canonical URI format (RFC 8707 Section 2)
- [ ] Store resource indicator with authorization request for later validation
- [ ] Bind issued access tokens to the specified resource (audience claim)
- [ ] Validate that resource indicator in token request matches authorization request
- [ ] Return appropriate error (`invalid_target`) for invalid resource indicators
- [ ] Update Protected Resource Metadata to include the resource identifier

## Acceptance Criteria

1. Authorization requests with `resource` parameter are accepted and validated
2. Token requests with `resource` parameter are validated against the stored authorization request
3. Access tokens include audience binding to the resource
4. Clients without `resource` parameter receive appropriate guidance
5. Invalid resource indicators return proper OAuth errors

## References

- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)
- [MCP Authorization - Resource Parameter Implementation](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
