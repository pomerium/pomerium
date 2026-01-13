---
id: client-id-metadata-documents
title: "OAuth Client ID Metadata Documents Support"
status: completed
created: 2026-01-06
updated: 2026-01-13
priority: high
labels:
  - mcp
  - oauth2
  - client-registration
deps: []
---

# OAuth Client ID Metadata Documents Support

## Summary

Implement OAuth Client ID Metadata Documents as specified in draft-ietf-oauth-client-id-metadata-document-00 to enable clients to use HTTPS URLs as client identifiers.

## Requirement (from MCP Specification)

> MCP clients and authorization servers **SHOULD** support OAuth Client ID Metadata Documents as specified in [OAuth Client ID Metadata Document](/.docs/RFC/draft-ietf-oauth-client-id-metadata-document.txt).

> This approach enables clients to use HTTPS URLs as client identifiers, where the URL points to a JSON document containing client metadata. This addresses the common MCP scenario where servers and clients have no pre-existing relationship.

## Use Case

Many MCP clients and servers have no prior relationship. Client ID Metadata Documents allow:
1. Client uses its metadata URL as `client_id` (e.g., `https://app.example.com/oauth/client-metadata.json`)
2. Authorization server fetches metadata from that URL
3. Authorization server validates redirect URIs against those in metadata
4. No pre-registration required

## Current State

**IMPLEMENTED.** The feature is fully implemented in the following files:

- `internal/mcp/client_id_metadata.go` - Core implementation including:
  - `IsClientIDMetadataURL()` - Detects URL-formatted client_ids
  - `ClientMetadataFetcher` - Fetches and validates metadata documents
  - `ClientIDMetadataDocument` - Struct representing the metadata document
  - Validation logic for client_id matching, redirect_uris, and auth methods
- `internal/mcp/domain_matcher.go` - Domain allowlist/blocklist for SSRF protection
- `internal/mcp/handler_authorization.go` - Integration with authorization flow via `getOrFetchClient()`
- `internal/mcp/handler_metadata.go` - Advertises `client_id_metadata_document_supported: true`

E2E tests are available in `internal/mcp/e2e/mcp_client_id_metadata_test.go`.

## Implementation Tasks

- [x] Detect URL-formatted client_ids in authorization requests
- [x] Fetch metadata document from client_id URL
- [x] Validate metadata document structure (required fields: client_id, client_name, redirect_uris)
- [x] Validate that `client_id` in document matches the URL exactly
- [x] Validate redirect_uri in authorization request against metadata
- [ ] Cache metadata documents respecting HTTP cache headers (not yet implemented)
- [x] Advertise support via `client_id_metadata_document_supported` in AS metadata
- [x] Implement SSRF protections when fetching metadata (via DomainMatcher)
- [x] Handle fetch failures gracefully

## Example Client Metadata Document

```json
{
  "client_id": "https://app.example.com/oauth/client-metadata.json",
  "client_name": "Example MCP Client",
  "client_uri": "https://app.example.com",
  "logo_uri": "https://app.example.com/logo.png",
  "redirect_uris": [
    "http://127.0.0.1:3000/callback",
    "http://localhost:3000/callback"
  ],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

## Security Considerations

- SSRF protection when fetching metadata
- Validate HTTPS scheme for client_id URLs
- Display warnings for localhost-only redirect URIs
- Show client metadata prominently during authorization

## Acceptance Criteria

1. ✅ URL-formatted client_ids are recognized and metadata is fetched
2. ✅ Metadata document validation is complete and secure
3. ✅ Redirect URI validation uses metadata document
4. ✅ `client_id_metadata_document_supported` is advertised
5. ⚠️ Caching respects HTTP cache headers (not yet implemented)
6. ✅ SSRF protections are in place (via DomainMatcher allowlist)

## References

- [OAuth Client ID Metadata Document Draft](/.docs/RFC/draft-ietf-oauth-client-id-metadata-document.txt)
- [MCP Authorization - Client ID Metadata Documents](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-06: Split domain trust policy configuration into `client-id-metadata-trust-policy`
- 2026-01-13: Updated status to completed - feature is implemented in `internal/mcp/client_id_metadata.go`
