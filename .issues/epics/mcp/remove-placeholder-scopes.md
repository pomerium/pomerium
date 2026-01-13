---
id: remove-placeholder-scopes
title: "Remove Placeholder Scopes from Pomerium AS Metadata"
status: open
created: 2026-01-13
updated: 2026-01-13
priority: low
labels:
  - optional
  - mcp
  - oauth2
  - cleanup
deps: []
---

# Remove Placeholder Scopes from Pomerium AS Metadata

## Summary

Remove the hardcoded `["openid", "offline"]` scopes from Pomerium's Authorization Server and Protected Resource metadata since they are not enforced and have no functional meaning.

## Current State

Pomerium advertises scopes that it doesn't actually use or enforce:

**Authorization Server Metadata** (`handler_metadata.go:166`):
```go
ScopesSupported: []string{"openid", "offline"},
```

**Protected Resource Metadata** (`handler_metadata.go:183`):
```go
ScopesSupported: []string{"openid", "offline"},
```

These scopes:
- Are not validated during authorization requests
- Are not included in issued tokens
- Have no effect on access control
- Could mislead MCP clients about Pomerium's capabilities

## Context: Scope Separation

There are two distinct scope contexts in Pomerium's MCP implementation:

| Context | Location | Purpose |
|---------|----------|---------|
| **Pomerium AS scopes** | `scopes_supported` in metadata | Scopes MCP clients can request from Pomerium |
| **Upstream OAuth scopes** | `upstream_oauth2.scopes` in config | Scopes Pomerium requests from upstream providers (Google, etc.) |

The `upstream_oauth2.scopes` are meaningful - they define initial scopes for upstream OAuth flows. The Pomerium AS scopes (`openid`, `offline`) are placeholders with no implementation.

## Recommendation

Remove or empty the `scopes_supported` field until Pomerium has a real use case for its own scope enforcement.

Per RFC 8414, `scopes_supported` is RECOMMENDED but not REQUIRED:
> scopes_supported: JSON array containing a list of the OAuth 2.0 "scope" values that this authorization server supports. [...] If omitted, servers MAY still support scopes not listed.

## Implementation Tasks

- [ ] Remove `ScopesSupported` from `getAuthorizationServerMetadata()` in `handler_metadata.go:166`
- [ ] Remove `ScopesSupported` from `getProtectedResourceMetadata()` in `handler_metadata.go:183`
- [ ] Update any tests that expect these scopes
- [ ] Verify MCP clients handle missing `scopes_supported` gracefully

## Files to Modify

- `internal/mcp/handler_metadata.go`
- `internal/mcp/handler_metadata_test.go` (if applicable)

## Acceptance Criteria

1. `scopes_supported` is not present in Authorization Server Metadata (or is empty)
2. `scopes_supported` is not present in Protected Resource Metadata (or is empty)
3. MCP clients continue to work without `scopes_supported`

## Future Considerations

If Pomerium later needs its own scope system (e.g., for fine-grained MCP tool permissions), a new ticket should be created to design and implement meaningful scopes.

## References

- [RFC 8414 - OAuth 2.0 Authorization Server Metadata](/.docs/RFC/rfc8414.txt)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](/.docs/RFC/rfc9728.txt)

## Log

- 2026-01-13: Issue created - remove placeholder scopes that have no functional meaning
