---
id: client-id-metadata-trust-policy
title: "Client ID Metadata Document Trust Policy (Allowlist/Blocklist)"
status: open
created: 2026-01-06
updated: 2026-01-06
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

## Requirements

- Provide a configuration mechanism for operators to specify:
  - An allowlist of domains (or host patterns)
  - A blocklist of domains (or host patterns)
- Apply the policy when fetching the metadata document from the `client_id` URL.
- Define clear precedence rules when both allowlist and blocklist are configured.

## Implementation Tasks

- [ ] Define configuration schema for allowlist/blocklist
- [ ] Implement host extraction and normalization for `client_id` URLs
- [ ] Enforce trust policy during metadata document fetch
- [ ] Define precedence rules (e.g., blocklist wins over allowlist)
- [ ] Add unit tests for trust policy evaluation
- [ ] Document configuration and examples

## Acceptance Criteria

1. Operators can configure allowlist and/or blocklist rules
2. Fetches are denied when the `client_id` host is not trusted
3. Precedence is well-defined and covered by tests
4. Denials surface as a clear OAuth error response (and are auditable via logs)

## Log

- 2026-01-06: Issue created by splitting trust policy work out of `client-id-metadata-documents`
