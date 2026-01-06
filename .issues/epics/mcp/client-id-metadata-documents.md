---
id: client-id-metadata-documents
title: "OAuth Client ID Metadata Documents Support"
status: open
created: 2026-01-06
updated: 2026-01-06
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

> MCP clients and authorization servers **SHOULD** support OAuth Client ID Metadata Documents as specified in [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00).

> This approach enables clients to use HTTPS URLs as client identifiers, where the URL points to a JSON document containing client metadata. This addresses the common MCP scenario where servers and clients have no pre-existing relationship.

## Use Case

Many MCP clients and servers have no prior relationship. Client ID Metadata Documents allow:
1. Client uses its metadata URL as `client_id` (e.g., `https://app.example.com/oauth/client-metadata.json`)
2. Authorization server fetches metadata from that URL
3. Authorization server validates redirect URIs against those in metadata
4. No pre-registration required

## Current State

The current implementation supports Dynamic Client Registration (RFC 7591) but not Client ID Metadata Documents.

## Implementation Tasks

- [ ] Detect URL-formatted client_ids in authorization requests
- [ ] Fetch metadata document from client_id URL
- [ ] Validate metadata document structure (required fields: client_id, client_name, redirect_uris)
- [ ] Validate that `client_id` in document matches the URL exactly
- [ ] Validate redirect_uri in authorization request against metadata
- [ ] Cache metadata documents respecting HTTP cache headers
- [ ] Advertise support via `client_id_metadata_document_supported` in AS metadata
- [ ] Implement SSRF protections when fetching metadata
- [ ] Add trust policy configuration (allowlist/blocklist domains)
- [ ] Handle fetch failures gracefully

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
- Domain-based trust policies
- Display warnings for localhost-only redirect URIs
- Show client metadata prominently during authorization

## Acceptance Criteria

1. URL-formatted client_ids are recognized and metadata is fetched
2. Metadata document validation is complete and secure
3. Redirect URI validation uses metadata document
4. `client_id_metadata_document_supported` is advertised
5. Caching respects HTTP cache headers
6. SSRF protections are in place
7. Trust policy configuration is available

## References

- [OAuth Client ID Metadata Document Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00)
- [MCP Authorization - Client ID Metadata Documents](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
