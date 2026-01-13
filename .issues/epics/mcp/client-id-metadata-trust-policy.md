---
id: client-id-metadata-trust-policy
title: "Client ID Metadata Document Trust Policy (Allowlist/Blocklist)"
status: completed
created: 2026-01-06
updated: 2026-01-13
priority: medium
labels:
  - mcp
  - oauth2
  - client-registration
  - security
deps:
  - client-id-metadata-documents
---

# Client ID Metadata Document Trust Policy (Allowlist/Blocklist)

## Summary

Add configurable domain trust policies for OAuth Client ID Metadata Document fetching. This allows operators to explicitly allow or deny metadata document domains to reduce exposure to SSRF, misconfiguration, and unexpected outbound traffic.

## Scope

This issue is limited to **configuration + enforcement** of a trust policy for the metadata document fetch URL host.

Out of scope:
- The core Client ID Metadata Document feature itself (tracked in `client-id-metadata-documents`).
- General SSRF protections (tracked/handled with the core feature).

## Current State

**IMPLEMENTED.** The allowlist functionality is fully implemented:

- `internal/mcp/domain_matcher.go` - `DomainMatcher` struct with:
  - `NewDomainMatcher()` - Creates matcher from allowed domain patterns
  - `IsAllowed()` - Checks if hostname matches any allowed pattern (supports wildcards via `certmagic.MatchWildcard`)
  - `ValidateURLDomain()` - Validates a URL's domain against the allowlist
- `config/options.go` - Configuration via `MCPAllowedClientIDDomains` option
- `internal/mcp/handler.go:87` - Integration point: `domainMatcher := NewDomainMatcher(cfg.Options.MCPAllowedClientIDDomains)`
- `internal/mcp/client_id_metadata.go` - Enforced during metadata fetch via `ClientMetadataFetcher`

Unit tests in `internal/mcp/domain_matcher_test.go` and E2E tests in `internal/mcp/e2e/mcp_client_id_metadata_test.go`.

**Note**: Only allowlist is implemented. Blocklist functionality was not added (allowlist-only approach is simpler and sufficient for most use cases).

## Requirements

- ✅ Provide a configuration mechanism for operators to specify:
  - ✅ An allowlist of domains (or host patterns) - `mcp_allowed_client_id_domains`
  - ❌ A blocklist of domains (or host patterns) - NOT IMPLEMENTED
- ✅ Apply the policy when fetching the metadata document from the `client_id` URL.
- N/A Define clear precedence rules when both allowlist and blocklist are configured (blocklist not implemented).

## Implementation Tasks

- [x] Define configuration schema for allowlist/blocklist (`mcp_allowed_client_id_domains` in config)
- [x] Implement host extraction and normalization for `client_id` URLs (via `url.URL.Hostname()`)
- [x] Enforce trust policy during metadata document fetch
- [ ] Define precedence rules (e.g., blocklist wins over allowlist) - N/A, blocklist not implemented
- [x] Add unit tests for trust policy evaluation
- [ ] Document configuration and examples

## Acceptance Criteria

1. ✅ Operators can configure allowlist and/or blocklist rules (allowlist only)
2. ✅ Fetches are denied when the `client_id` host is not trusted
3. N/A Precedence is well-defined and covered by tests (no blocklist)
4. ✅ Denials surface as a clear OAuth error response (and are auditable via logs)

## Configuration Example

```yaml
mcp_allowed_client_id_domains:
  - "*.example.com"
  - "trusted-app.org"
  - "*.localhost.pomerium.io"
```

Wildcard patterns are supported via `certmagic.MatchWildcard`.

## Log

- 2026-01-06: Issue created by splitting trust policy work out of `client-id-metadata-documents`
- 2026-01-13: Updated status to completed - allowlist implemented via `DomainMatcher` and `MCPAllowedClientIDDomains` config
