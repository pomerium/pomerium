---
id: upstream-oauth-client-flow
title: "OAuth 2.1 Client Flow Implementation"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: high
labels:
  - mcp
  - proxy
  - oauth2
  - pkce
deps:
  - upstream-discovery
  - per-route-cimd-hosting
---

# OAuth 2.1 Client Flow Implementation

## Summary

Implement the OAuth 2.1 Authorization Code flow with PKCE for Pomerium acting as an MCP client to remote authorization servers. This is the core OAuth client implementation used by the authorization choreographer.

## Requirements

From the MCP specification:
> MCP clients MUST implement OAuth 2.1 with PKCE (RFC 7636) for authorization

## OAuth 2.1 Flow

```
┌──────────┐                                          ┌──────────────┐
│ Pomerium │                                          │  Remote AS   │
│ (Client) │                                          │              │
└────┬─────┘                                          └──────┬───────┘
     │                                                       │
     │ 1. Authorization Request                              │
     │    GET /authorize                                     │
     │    ?client_id={cimd_url}                             │
     │    &redirect_uri={callback}                          │
     │    &response_type=code                               │
     │    &state={random}                                   │
     │    &code_challenge={challenge}                       │
     │    &code_challenge_method=S256                       │
     │    &scope={scopes}                                   │
     │    &resource={upstream_server}                       │
     │─────────────────────────────────────────────────────>│
     │                                                       │
     │ 2. User authenticates & consents                     │
     │                                                       │
     │ 3. Authorization Response                             │
     │    302 Redirect to callback                          │
     │    ?code={auth_code}                                 │
     │    &state={random}                                   │
     │<─────────────────────────────────────────────────────│
     │                                                       │
     │ 4. Token Request                                      │
     │    POST /token                                       │
     │    grant_type=authorization_code                     │
     │    &code={auth_code}                                 │
     │    &redirect_uri={callback}                          │
     │    &client_id={cimd_url}                             │
     │    &code_verifier={verifier}                         │
     │─────────────────────────────────────────────────────>│
     │                                                       │
     │ 5. Token Response                                     │
     │    {access_token, refresh_token, expires_in, ...}   │
     │<─────────────────────────────────────────────────────│
     │                                                       │
```

## PKCE Implementation

```go
// Generate code verifier (43-128 chars, unreserved URI chars)
codeVerifier := generateSecureRandom(32) // base64url encoded

// Generate code challenge (SHA256 of verifier, base64url encoded)
hash := sha256.Sum256([]byte(codeVerifier))
codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
codeChallengeMethod := "S256"
```

## Implementation Tasks

### PKCE
- [ ] Implement secure code verifier generation (RFC 7636 Appendix B)
- [ ] Implement S256 code challenge generation
- [ ] Store code verifier securely for token exchange

### Authorization Request
- [ ] Build authorization URL with all required parameters
- [ ] Include `resource` parameter per RFC 8707
- [ ] Include scopes from discovery
- [ ] Generate and include state parameter
- [ ] Support optional parameters (e.g., `prompt`, `login_hint`)

### Token Request
- [ ] Implement token endpoint request
- [ ] Include authorization code
- [ ] Include code verifier (PKCE)
- [ ] Include client_id (CIMD URL)
- [ ] Handle form-urlencoded request body
- [ ] Parse JSON token response

### Token Response Handling
- [ ] Parse access_token
- [ ] Parse refresh_token (if present)
- [ ] Parse expires_in
- [ ] Parse token_type
- [ ] Parse scope (may differ from requested)
- [ ] Handle error responses

### Refresh Token Flow
- [ ] Implement refresh_token grant type
- [ ] Include client_id in refresh request
- [ ] Handle refresh token rotation (new refresh token in response)
- [ ] Handle refresh failures (trigger re-authorization)

### Error Handling
- [ ] Parse OAuth error responses
- [ ] Map errors to appropriate actions:
  - `invalid_grant` → Re-authorize
  - `invalid_client` → Configuration error
  - `access_denied` → User denied consent
  - `invalid_scope` → Scope negotiation needed
- [ ] Provide clear error messages

## Acceptance Criteria

1. Full OAuth 2.1 authorization code flow works end-to-end
2. PKCE is always used (S256 method)
3. Resource indicator is included per RFC 8707
4. Token response is parsed and stored correctly
5. Refresh token flow works
6. All OAuth errors are handled appropriately
7. No client secrets are used (public client)

## Security Considerations

- Code verifier MUST be cryptographically random
- Code verifier MUST NOT be transmitted except to token endpoint
- State MUST be validated on callback
- Tokens MUST NOT be logged

## References

- [OAuth 2.1 Draft](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [RFC 7636 - PKCE](/.docs/RFC/rfc7636.txt)
- [RFC 8707 - Resource Indicators](/.docs/RFC/rfc8707.txt)
- [MCP Proxy Epic](./index.md)

## Log

- 2026-01-26: Issue created from epic breakdown
