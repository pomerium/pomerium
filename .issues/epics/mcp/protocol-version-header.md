---
id: protocol-version-header
title: "MCP Protocol Version Header Support"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: medium
labels:
  - mcp
  - protocol
deps: []
---

# MCP Protocol Version Header Support

## Summary

Implement proper handling of the `MCP-Protocol-Version` HTTP header for protocol version negotiation and validation.

## Requirement (from MCP Specification)

> If using HTTP, the client **MUST** include the `MCP-Protocol-Version: <protocol-version>` HTTP header on all subsequent requests to the MCP server, allowing the MCP server to respond based on the MCP protocol version.
>
> For example: `MCP-Protocol-Version: 2025-11-25`
>
> The protocol version sent by the client **SHOULD** be the one negotiated during initialization.
>
> For backwards compatibility, if the server does _not_ receive an `MCP-Protocol-Version` header, and has no other way to identify the version, the server **SHOULD** assume protocol version `2025-03-26`.
>
> If the server receives a request with an invalid or unsupported `MCP-Protocol-Version`, it **MUST** respond with `400 Bad Request`.

## Current State

The current CORS configuration allows the `mcp-protocol-version` header:
```go
AllowedHeaders: []string{"content-type", "mcp-protocol-version"},
```

But the header is not validated or used for versioned behavior.

## Implementation Tasks

- [ ] Parse `MCP-Protocol-Version` header from incoming requests
- [ ] Validate version format (YYYY-MM-DD)
- [ ] Check version against supported versions list
- [ ] Return HTTP 400 for invalid/unsupported versions
- [ ] Default to `2025-03-26` when header is missing (backward compatibility)
- [ ] Store negotiated version in session for consistency
- [ ] Implement version-specific behavior paths if needed
- [ ] Document supported protocol versions
- [ ] Add version to responses where appropriate

## Supported Versions

Based on the MCP changelog:
- `2025-11-25` (current)
- `2025-06-18`
- `2025-03-26` (default fallback)
- `2024-11-05` (HTTP+SSE transport)

## Example Validation

```go
var supportedVersions = map[string]bool{
    "2025-11-25": true,
    "2025-06-18": true,
    "2025-03-26": true,
}

func validateProtocolVersion(version string) error {
    if version == "" {
        return nil // Will use default
    }
    if !supportedVersions[version] {
        return fmt.Errorf("unsupported protocol version: %s", version)
    }
    return nil
}
```

## Acceptance Criteria

1. Protocol version header is parsed from all requests
2. Invalid versions return HTTP 400
3. Missing header defaults to 2025-03-26
4. Supported versions are documented
5. Version-specific behavior can be implemented if needed
6. Tests cover version validation

## References

- [MCP Transports - Protocol Version Header](/.docs/mcp/basic/transports.mdx)
- [MCP Lifecycle - Version Negotiation](/.docs/mcp/basic/lifecycle.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
