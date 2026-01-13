---
id: client-registration-validation
title: "Enhanced Client Registration Validation"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: medium
labels:
  - mcp
  - oauth2
  - security
deps: []
---

# Enhanced Client Registration Validation

## Summary

Enhance the dynamic client registration endpoint with additional validation and security measures as specified in RFC 7591 and MCP security guidelines.

## Requirement

From RFC 7591 and MCP Security Best Practices:
- Validate all client metadata fields
- Enforce redirect URI restrictions
- Prevent open redirection attacks
- Implement rate limiting
- Consider software statements for attestation

## Current State

The current `handler_register_client.go` implements basic validation:
- Parses client metadata
- Validates required fields
- Sets defaults for optional fields
- Generates client secret for non-public clients

## Implementation Tasks

### Redirect URI Validation
- [ ] Enforce HTTPS for non-localhost redirect URIs
- [ ] Allow `localhost` and `127.0.0.1` for local development
- [ ] Validate exact redirect URI matching (no patterns)
- [ ] Block dangerous URI schemes (javascript:, data:, etc.)
- [ ] Validate URI format and structure

### Additional Validation
- [ ] Validate `client_name` length and character restrictions
- [ ] Validate `logo_uri` if provided (HTTPS, proper format)
- [ ] Validate `client_uri` if provided
- [ ] Validate `grant_types` against supported types
- [ ] Validate `response_types` against supported types
- [ ] Validate `token_endpoint_auth_method` is supported

### Security Measures
- [ ] Implement rate limiting on registration endpoint
- [ ] Consider IP-based throttling
- [ ] Add optional software statement validation
- [ ] Log registration attempts for audit
- [ ] Consider registration policies (open vs. protected)

### Response Enhancements
- [ ] Return `client_id_issued_at` timestamp
- [ ] Return `client_secret_expires_at` if applicable
- [ ] Include all registered metadata in response

## Redirect URI Rules

```go
func validateRedirectURI(uri string) error {
    parsed, err := url.Parse(uri)
    if err != nil {
        return fmt.Errorf("invalid URI: %w", err)
    }

    // Allow localhost for development
    if parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" {
        return nil
    }

    // Require HTTPS for all other URIs
    if parsed.Scheme != "https" {
        return fmt.Errorf("redirect_uri must use HTTPS")
    }

    // Block dangerous schemes
    if strings.HasPrefix(uri, "javascript:") || strings.HasPrefix(uri, "data:") {
        return fmt.Errorf("redirect_uri uses forbidden scheme")
    }

    return nil
}
```

## Acceptance Criteria

1. All redirect URIs are validated per OAuth 2.1 requirements
2. Client metadata fields are validated for format and length
3. Rate limiting prevents registration abuse
4. Registration responses include all required fields
5. Security logging captures registration events
6. Documentation covers registration requirements

## References

- [RFC 7591 - OAuth 2.0 Dynamic Client Registration](/.docs/RFC/rfc7591.txt)
- [OAuth 2.1 Section 2.1 - Client Registration](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [MCP Authorization - Dynamic Client Registration](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created from MCP spec gap analysis
- 2026-01-13: Reviewed - basic validation exists in handler_register_client.go, but enhanced validation (redirect URI schemes, rate limiting) not yet implemented
