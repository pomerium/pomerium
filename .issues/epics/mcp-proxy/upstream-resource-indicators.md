---
id: upstream-resource-indicators
title: "RFC 8707 Resource Indicators for Upstream Tokens"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: high
labels:
  - mcp
  - proxy
  - security
  - rfc8707
deps:
  - upstream-oauth-client-flow
---

# RFC 8707 Resource Indicators for Upstream Tokens

## Summary

Implement RFC 8707 Resource Indicators when Pomerium (as MCP client) acquires tokens from remote authorization servers. This ensures tokens are bound to the specific upstream MCP server, preventing token reuse attacks.

## Requirements

From the epic:
> **Confused Deputy Protection**:
> - Resource indicators (RFC 8707) MUST be used when acquiring upstream tokens
> - Token audience MUST match the upstream server

From MCP Specification:
> MCP clients MUST implement Resource Indicators for OAuth 2.0 as defined in RFC 8707

## Resource Parameter Usage

When initiating authorization with a remote AS:

```
Authorization Request:
GET /authorize
  ?client_id=https://mcp.example.com/.well-known/mcp-client-metadata.json
  &resource=https://remote-mcp.provider.com
  &redirect_uri=https://mcp.example.com/.pomerium/oauth/callback
  &response_type=code
  &...
```

Token Request:
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={code}
&client_id=https://mcp.example.com/.well-known/mcp-client-metadata.json
&resource=https://remote-mcp.provider.com
&code_verifier={verifier}
```

## Resource Identifier Derivation

The resource identifier should be the canonical URL of the upstream MCP server:

```go
func deriveResourceIdentifier(route *config.Route) string {
    // Use the upstream server's base URL
    // Per RFC 8707 Section 2: MUST be an absolute URI
    upstreamURL, _ := url.Parse(route.To)
    return fmt.Sprintf("%s://%s", upstreamURL.Scheme, upstreamURL.Host)
}
```

## Token Audience Validation

When using stored upstream tokens:

```go
func validateTokenAudience(token *UpstreamToken, upstreamServer string) error {
    // Verify token was issued for this specific upstream
    if token.Audience != upstreamServer {
        return ErrAudienceMismatch
    }
    return nil
}
```

## Implementation Tasks

### Authorization Request
- [ ] Include `resource` parameter in authorization request
- [ ] Derive resource identifier from route's `to:` URL
- [ ] Ensure resource is an absolute URI per RFC 8707

### Token Request
- [ ] Include `resource` parameter in token request
- [ ] Validate resource matches authorization request

### Token Storage
- [ ] Store audience/resource with acquired token
- [ ] Include audience in token cache key

### Token Validation
- [ ] Validate token audience before use
- [ ] Reject tokens with mismatched audience
- [ ] Handle tokens without audience claim (legacy AS)

### AS Capability Detection
- [ ] Check if remote AS supports resource indicators
- [ ] Handle AS that doesn't support resource parameter
- [ ] Log warning for non-supporting AS

## Error Handling

| Error | Cause | Action |
|-------|-------|--------|
| `invalid_target` | Invalid resource identifier | Check resource URI format |
| `access_denied` | AS rejected resource | May need to use different resource |
| Token without audience | Legacy AS | Accept with warning, log for audit |

## Acceptance Criteria

1. Resource parameter is included in all authorization requests
2. Resource parameter is included in all token requests
3. Tokens are stored with audience information
4. Token audience is validated before every use
5. Tokens cannot be reused for different upstream servers
6. Legacy AS (no resource support) is handled gracefully

## Security Impact

Without resource indicators:
- Token acquired for Server A could potentially be used for Server B
- Confused deputy attacks possible if AS issues broad tokens

With resource indicators:
- Tokens are bound to specific upstream server
- Token reuse across servers is prevented
- Defense in depth against token confusion

## References

- [RFC 8707 - Resource Indicators for OAuth 2.0](/.docs/RFC/rfc8707.txt)
- [Resource Indicator Support (MCP Epic)](../mcp/resource-indicator-support.md)
- [MCP Proxy Epic](./index.md)

## Log

- 2026-01-26: Issue created from epic breakdown
