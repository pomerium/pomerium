---
id: upstream-resource-indicators
title: "RFC 8707 Resource Indicators for Upstream Tokens"
status: open
created: 2026-01-26
updated: 2026-02-02
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

## Normative References

### MCP Authorization Spec (/.docs/mcp/basic/authorization.mdx)

> **Section: Resource Parameter Implementation**
> "MCP clients **MUST** implement Resource Indicators for OAuth 2.0 as defined in RFC 8707 to explicitly specify the target resource for which the token is being requested. The `resource` parameter:
> 1. **MUST** be included in both authorization requests and token requests.
> 2. **MUST** identify the MCP server that the client intends to use the token with.
> 3. **MUST** use the canonical URI of the MCP server as defined in RFC 8707 Section 2."

> **Section: Canonical Server URI**
> "MCP clients **SHOULD** provide the most specific URI that they can for the MCP server they intend to access... Examples of valid canonical URIs:
> - `https://mcp.example.com/mcp`
> - `https://mcp.example.com`
> - `https://mcp.example.com:8443`"

> **Section: Token Audience Binding and Validation**
> "MCP servers **MUST** validate that tokens presented to them were specifically issued for their use... MCP clients **MUST** include the `resource` parameter in authorization and token requests as specified."

> **Section: Access Token Privilege Restriction**
> "MCP servers **MUST** validate access tokens before processing the request, ensuring the access token is issued specifically for the MCP server... MCP servers **MUST** only accept tokens specifically intended for themselves and **MUST** reject tokens that do not include them in the audience claim."

### RFC 8707 - Resource Indicators (/.docs/RFC/rfc8707.txt)

> **Section 2 - Access Token Request**: "The value of the `resource` parameter MUST be an absolute URI... It SHOULD NOT include a query component or fragment component."

## Implementation Reasoning

### Why Resource Indicators are Critical

Per MCP spec, without resource indicators:
1. A token acquired for Server A could potentially be used for Server B (confused deputy)
2. Broad tokens enable token reuse attacks across services
3. Audience validation becomes impossible

The MCP spec explicitly states this is a **MUST** requirement - not optional.

### Canonical URI Derivation

From the route configuration, derive the resource identifier:

```go
// Per MCP spec: "use the canonical URI of the MCP server"
// Per RFC 8707: "MUST be an absolute URI"
func deriveResourceIdentifier(route *config.Policy) string {
    u, _ := url.Parse(route.GetTo()) // The upstream MCP server

    // MCP spec examples use full path when relevant
    // e.g., "https://mcp.example.com/mcp" not just host
    canonical := &url.URL{
        Scheme: u.Scheme,
        Host:   u.Host,
        Path:   u.Path, // Include path per MCP spec examples
    }

    // Per MCP spec: "without trailing slash" for better interoperability
    return strings.TrimSuffix(canonical.String(), "/")
}
```

### Integration with Token Storage

The resource/audience must be stored with the token for validation:

```go
// Extend UpstreamMCPToken in storage.go
type UpstreamMCPToken struct {
    // ... existing fields ...
    Resource string // The resource indicator used when acquiring this token
}

// Before using any stored token, validate audience
func (s *Storage) GetUpstreamOAuth2Token(ctx context.Context, key TokenKey, expectedResource string) (*oauth2.Token, error) {
    token, err := s.getToken(ctx, key)
    if err != nil {
        return nil, err
    }
    if token.Resource != expectedResource {
        return nil, ErrAudienceMismatch
    }
    return token, nil
}
```

## Resource Parameter Usage

### Authorization Request
```
GET /authorize
  ?client_id=https://mcp.example.com/.pomerium/mcp/client/metadata.json
  &resource=https://remote-mcp.provider.com/mcp  ← REQUIRED per MCP spec
  &redirect_uri=https://mcp.example.com/.pomerium/mcp/client/oauth/callback
  &response_type=code
  &code_challenge=...
  &code_challenge_method=S256
  &scope=mcp:read mcp:write
  &state=...
```

### Token Request
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={code}
&client_id=https://mcp.example.com/.pomerium/mcp/client/metadata.json
&resource=https://remote-mcp.provider.com/mcp  ← REQUIRED per MCP spec
&code_verifier={verifier}
&redirect_uri=https://mcp.example.com/.pomerium/mcp/client/oauth/callback
```

### Refresh Token Request
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token={refresh_token}
&client_id=https://mcp.example.com/.pomerium/mcp/client/metadata.json
&resource=https://remote-mcp.provider.com/mcp  ← Include on refresh too
```

## Implementation Tasks

### Resource Derivation
- [ ] Implement `deriveResourceIdentifier()` from route's `to:` URL
- [ ] Ensure resource is an absolute URI per RFC 8707 §2
- [ ] Include path component when relevant (per MCP spec examples)
- [ ] Normalize: no trailing slash, no query/fragment per RFC 8707

### Authorization Request
- [ ] Include `resource` parameter in authorization request (MUST)
- [ ] Use derived canonical URI
- [ ] Log resource being requested for debugging

### Token Request
- [ ] Include `resource` parameter in token request (MUST)
- [ ] Ensure resource matches authorization request exactly
- [ ] Include resource in refresh token requests

### Token Storage
- [ ] Store resource/audience with acquired token
- [ ] Include resource in token cache key for isolation
- [ ] Extend protobuf schema if needed

### Token Validation (per MCP spec: "MUST validate")
- [ ] Validate token resource/audience before every use
- [ ] Reject tokens with mismatched audience
- [ ] Log audience validation failures as security events

### AS Capability Handling
- [ ] Handle AS that doesn't support resource parameter gracefully
- [ ] Log warning for non-supporting AS (reduced security)
- [ ] Consider failing fast if AS ignores resource (configurable?)

## Error Handling

| Error | Cause | Action | MCP Spec Reference |
|-------|-------|--------|-------------------|
| `invalid_target` | Invalid resource URI format | Fix URI derivation | RFC 8707 §2 |
| `access_denied` | AS rejected resource | Check AS configuration | RFC 8707 §5 |
| Audience mismatch | Token not for this server | Re-acquire token | MCP Auth: "MUST validate" |
| No resource support | Legacy AS | Accept with warning + audit | Document security trade-off |

## Acceptance Criteria

1. Resource parameter is included in ALL authorization requests (MCP: MUST)
2. Resource parameter is included in ALL token requests (MCP: MUST)
3. Resource parameter is included in refresh token requests
4. Tokens are stored with resource/audience binding
5. Token audience is validated before EVERY use (MCP: MUST validate)
6. Mismatched audience tokens are rejected
7. Audit log captures resource binding and validation events

## Security Impact

Per MCP spec "Access Token Privilege Restriction" section:

| Threat | Without Resource Indicators | With Resource Indicators |
|--------|----------------------------|--------------------------|
| Token reuse across servers | Possible | Prevented |
| Confused deputy attack | Possible | Prevented |
| Audience validation | Impossible | Enforced |
| Cross-route token leakage | Possible | Prevented per-resource |

## Test Scenarios

| Scenario | Expected Behavior |
|----------|-------------------|
| Auth request without resource | Test should fail (MCP MUST) |
| Token with wrong audience | Rejected before use |
| Refresh request without resource | Include resource per best practice |
| AS ignores resource parameter | Token acquired, but log warning |

## References

- [RFC 8707 - Resource Indicators for OAuth 2.0](/.docs/RFC/rfc8707.txt)
- [MCP Authorization Spec](/.docs/mcp/basic/authorization.mdx) - Primary normative reference
- [MCP Proxy Epic](./index.md)
- Related: [token-isolation-enforcement](./token-isolation-enforcement.md)

## Log

- 2026-02-02: Added normative references with direct quotes, implementation reasoning
- 2026-01-26: Issue created from epic breakdown
