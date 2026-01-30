---
id: e2e-conformance-test-coverage
title: "MCP E2E Conformance Test Coverage"
status: open
created: 2026-01-19
updated: 2026-01-26
priority: high
labels:
  - mcp
  - testing
  - oauth2
  - security
deps: []
---

# MCP E2E Conformance Test Coverage

## Summary

Add comprehensive E2E tests for MCP OAuth 2.1 features that are implemented but lack test coverage, particularly security-critical error handling paths. This ensures Pomerium's MCP implementation conforms to the MCP Authorization specification and aligns with the [official MCP Conformance Suite](https://github.com/modelcontextprotocol/conformance).

## Background

### Current E2E Test Coverage

The existing tests in `internal/mcp/e2e/` cover happy path flows:
- `mcp_auth_flow_test.go` - Full authorization code flow with PKCE and refresh tokens
- `mcp_client_id_metadata_test.go` - Client ID Metadata Documents flow and validation
- `mcp_test.go` - MCP tool invocation with policies

### MCP Conformance Suite Structure

The official conformance suite at [modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance) tests MCP **clients** against a mock authorization server. Key test scenarios include:

| Conformance Scenario | File | What It Tests |
|---------------------|------|---------------|
| `token-endpoint-auth` | `src/scenarios/client/auth/token-endpoint-auth.ts` | Client uses correct auth method (basic, post, none) |
| `discovery-metadata` | `src/scenarios/client/auth/discovery-metadata.ts` | OAuth/OIDC metadata discovery priority |
| `scope-handling` | `src/scenarios/client/auth/scope-handling.ts` | Scope selection from WWW-Authenticate, step-up auth |
| `basic-cimd` | `src/scenarios/client/auth/basic-cimd.ts` | Client ID Metadata Document usage |

Since Pomerium is the **authorization server** (not an MCP client), we need equivalent tests that verify Pomerium correctly:
1. Validates client authentication methods
2. Rejects invalid requests with proper OAuth 2.1 error codes
3. Enforces security constraints (PKCE, code replay, token binding)

---

## Detailed Test Scenarios

### 1. Token Endpoint Authentication Methods

**Conformance Reference:** [`token-endpoint-auth.ts`](https://github.com/modelcontextprotocol/conformance/blob/main/src/scenarios/client/auth/token-endpoint-auth.ts)

The conformance suite validates that clients use the correct authentication method at the token endpoint. Pomerium advertises support for `client_secret_basic` and `none` in AS metadata (`handler_metadata.go:161`), but only `none` is tested.

#### Test: `TestTokenEndpointClientSecretBasic`

**Scenario:** Client registered with `token_endpoint_auth_method: client_secret_basic` must authenticate using HTTP Basic Authentication (RFC 6749 Section 2.3.1).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Setup                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Register client via POST /register with:                                 │
│    {                                                                        │
│      "redirect_uris": ["http://127.0.0.1:8080/callback"],                   │
│      "grant_types": ["authorization_code"],                                 │
│      "token_endpoint_auth_method": "client_secret_basic"                    │
│    }                                                                        │
│ 2. Store returned client_id and client_secret                               │
│ 3. Complete authorization flow to get authorization code                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Test Cases                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case A: Valid Basic Auth → 200 OK + tokens                                  │
│   POST /token                                                               │
│   Authorization: Basic base64(client_id:client_secret)                      │
│   Content-Type: application/x-www-form-urlencoded                           │
│   Body: grant_type=authorization_code&code=XXX&redirect_uri=...             │
│   Expected: 200 OK, {"access_token": "...", "token_type": "Bearer", ...}    │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case B: Missing Authorization header → 401 Unauthorized                     │
│   POST /token (no Authorization header)                                     │
│   Expected: 401, {"error": "invalid_client"}                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case C: Wrong client_secret → 401 Unauthorized                              │
│   Authorization: Basic base64(client_id:wrong_secret)                       │
│   Expected: 401, {"error": "invalid_client"}                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case D: Malformed Basic header (not base64) → 400 Bad Request               │
│   Authorization: Basic not-valid-base64!!!                                  │
│   Expected: 400, {"error": "invalid_request"}                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case E: Basic header without colon separator → 400 Bad Request              │
│   Authorization: Basic base64(client_id_only_no_colon)                      │
│   Expected: 400, {"error": "invalid_request"}                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Spec References:**
- [OAuth 2.1 Section 2.4.1](/.docs/RFC/draft-ietf-oauth-v2-1.txt) - Client Password (client_secret_basic)
- [RFC 6749 Section 2.3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1) - Client Password
- Conformance check: `token-endpoint-auth-method` in `token-endpoint-auth.ts`

**Implementation:** `handler_token.go:304-320`

---

### 2. PKCE Code Verifier Validation

**Conformance Reference:** [MCP Auth spec lines 600-611](/.docs/mcp/basic/authorization.mdx)

> MCP clients **MUST** implement PKCE according to OAuth 2.1 Section 7.5.2 and **MUST** verify PKCE support before proceeding with authorization. [...] MCP clients **MUST** use the `S256` code challenge method.

The authorization server MUST reject token requests where the `code_verifier` doesn't match the original `code_challenge`.

#### Test: `TestPKCECodeVerifierValidation`

**Scenario:** Authorization server rejects token exchange when PKCE verification fails.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Setup                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Generate code_verifier (random 64-char string)                           │
│ 2. Compute code_challenge = BASE64URL(SHA256(code_verifier))                │
│ 3. Complete authorization request with code_challenge + code_challenge_     │
│    method=S256                                                              │
│ 4. Receive authorization code                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Test Cases                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case A: Correct code_verifier → 200 OK                                      │
│   POST /token with code_verifier=<original_verifier>                        │
│   Expected: 200 OK, tokens returned                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case B: Wrong code_verifier → 400 invalid_grant                             │
│   POST /token with code_verifier=<different_random_string>                  │
│   Expected: 400, {"error": "invalid_grant"}                                 │
│   Security: Prevents authorization code interception attacks                │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case C: Missing code_verifier → 400 invalid_grant                           │
│   POST /token without code_verifier parameter                               │
│   Expected: 400, {"error": "invalid_grant"}                                 │
│   Note: Required because code_challenge was provided in auth request        │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case D: Empty code_verifier → 400 invalid_grant                             │
│   POST /token with code_verifier=                                           │
│   Expected: 400, {"error": "invalid_grant"}                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Spec References:**
- [MCP Auth - Authorization Code Protection](/.docs/mcp/basic/authorization.mdx) lines 596-611
- [OAuth 2.1 Section 7.5.2](/.docs/RFC/draft-ietf-oauth-v2-1.txt) - PKCE
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) - PKCE for OAuth

**Implementation:** `handler_token.go:152-157`, `code.go:CheckPKCE()`

---

### 3. Authorization Code Replay Protection

**Conformance Reference:** [OAuth 2.1 Section 4.1.3](/.docs/RFC/draft-ietf-oauth-v2-1.txt)

> The authorization server MUST return an access token only once for a given authorization code.

This prevents stolen authorization codes from being exchanged multiple times.

#### Test: `TestAuthorizationCodeReplayProtection`

**Scenario:** Authorization code can only be exchanged for tokens once.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Setup                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Complete authorization flow                                              │
│ 2. Receive authorization code                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Test Cases                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case A: First use of code → 200 OK                                          │
│   POST /token with code=<auth_code>                                         │
│   Expected: 200 OK, tokens returned                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case B: Second use of same code → 400 invalid_grant                         │
│   POST /token with code=<same_auth_code> (replay attempt)                   │
│   Expected: 400, {"error": "invalid_grant"}                                 │
│   Security: Code was already consumed and deleted from storage              │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case C: Code for different client_id → 400 invalid_grant                    │
│   Register second client, try to use first client's code                    │
│   POST /token with client_id=<client2>&code=<client1_code>                  │
│   Expected: 400, {"error": "invalid_grant"}                                 │
│   Security: Codes are bound to the client that requested them               │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Spec References:**
- [OAuth 2.1 Section 4.1.3](/.docs/RFC/draft-ietf-oauth-v2-1.txt) - Access Token Request
- Comment in `handler_token.go:161-162`: "The authorization server MUST return an access token only once"

**Implementation:** `handler_token.go:161-168` (DeleteAuthorizationRequest after use)

---

### 4. Refresh Token Security

**Conformance Reference:** [MCP Auth - Token Theft](/.docs/mcp/basic/authorization.mdx) lines 575-584

> For public clients, authorization servers **MUST** rotate refresh tokens as described in OAuth 2.1 Section 4.3.1.

Pomerium implements refresh token rotation and revocation checking. These paths need test coverage.

#### Test: `TestRefreshTokenSecurity`

**Scenario:** Refresh tokens are validated for revocation, expiry, and client binding.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Setup                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Complete authorization flow, receive access_token + refresh_token        │
│ 2. Use refresh_token to get new tokens (this rotates the refresh token)     │
│ 3. Store both old_refresh_token and new_refresh_token                       │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Test Cases                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case A: Valid refresh token → 200 OK + new tokens                           │
│   POST /token with grant_type=refresh_token&refresh_token=<new_token>       │
│   Expected: 200 OK, new access_token + rotated refresh_token                │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case B: Revoked (rotated-out) refresh token → 400 invalid_grant             │
│   POST /token with refresh_token=<old_token> (already rotated)              │
│   Expected: 400, {"error": "invalid_grant"}                                 │
│   Security: Old tokens are marked revoked after rotation                    │
│   Implementation: handler_token.go:399-406 checks refreshTokenRecord.Revoked│
├─────────────────────────────────────────────────────────────────────────────┤
│ Case C: Refresh token for different client → 400 invalid_grant              │
│   Register second client, try to use first client's refresh token           │
│   POST /token with client_id=<client2>&refresh_token=<client1_token>        │
│   Expected: 400, {"error": "invalid_grant"}                                 │
│   Implementation: handler_token.go:389-397                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case D: Malformed/invalid refresh token → 400 invalid_grant                 │
│   POST /token with refresh_token=<garbage_string>                           │
│   Expected: 400, {"error": "invalid_grant"}                                 │
│   Security: Decryption fails gracefully                                     │
│   Implementation: handler_token.go:348-353                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Spec References:**
- [OAuth 2.1 Section 4.3.1](/.docs/RFC/draft-ietf-oauth-v2-1.txt) - Refresh Token Rotation
- [MCP Auth - Token Theft](/.docs/mcp/basic/authorization.mdx) lines 575-584
- [RFC 9700 Section 4.14](/.docs/RFC/rfc9700.txt) - Refresh Token Protection

**Implementation:** `handler_token.go:325-511`

---

### 5. Access Token Validation

**Conformance Reference:** [MCP Auth lines 471-486](/.docs/mcp/basic/authorization.mdx)

> MCP servers **MUST** validate access tokens as described in OAuth 2.1 Section 5.2. [...] Invalid or expired tokens **MUST** receive a HTTP 401 response.

#### Test: `TestAccessTokenValidation`

**Scenario:** MCP server (Pomerium proxy) rejects invalid access tokens with 401.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Setup                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Configure MCP server route with policy                                   │
│ 2. Obtain valid access token via authorization flow                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Test Cases                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case A: Valid access token → 200 OK                                         │
│   GET /mcp-endpoint                                                         │
│   Authorization: Bearer <valid_token>                                       │
│   Expected: 200 OK, MCP response                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case B: Missing Authorization header → 401 + WWW-Authenticate               │
│   GET /mcp-endpoint (no Authorization header)                               │
│   Expected: 401, WWW-Authenticate: Bearer resource_metadata="..."           │
│   Note: This is the flow that triggers OAuth discovery                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case C: Invalid/garbage token → 401                                         │
│   Authorization: Bearer invalid-token-string                                │
│   Expected: 401 Unauthorized                                                │
│   Security: Token decryption/validation fails                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case D: Expired access token → 401                                          │
│   Authorization: Bearer <expired_token>                                     │
│   Expected: 401 Unauthorized                                                │
│   Note: May need time manipulation or short-lived test tokens               │
├─────────────────────────────────────────────────────────────────────────────┤
│ Case E: Token in query string (forbidden) → 401                             │
│   GET /mcp-endpoint?access_token=<token>                                    │
│   Expected: 401 (tokens MUST NOT be in URI per MCP Auth line 459)           │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Spec References:**
- [MCP Auth - Token Handling](/.docs/mcp/basic/authorization.mdx) lines 469-486
- [MCP Auth - Access tokens MUST NOT be in URI](/.docs/mcp/basic/authorization.mdx) line 459
- [OAuth 2.1 Section 5.2](/.docs/RFC/draft-ietf-oauth-v2-1.txt) - Access Token Validation
- [RFC 6750 Section 3](/.docs/RFC/rfc6750.txt) - WWW-Authenticate Response Header

**Implementation:** Proxy layer token validation

---

### 6. Scope Handling (Future)

**Conformance Reference:** [`scope-handling.ts`](https://github.com/modelcontextprotocol/conformance/blob/main/src/scenarios/client/auth/scope-handling.ts)

The conformance suite tests five scope scenarios. Pomerium doesn't currently include `scope` in WWW-Authenticate (tracked in `www-authenticate-header.md`). Once implemented:

| Conformance Check | Description |
|-------------------|-------------|
| `scope-from-www-authenticate` | Client uses scope from 401 WWW-Authenticate header |
| `scope-from-scopes-supported` | Fallback to PRM's `scopes_supported` |
| `scope-omitted-when-undefined` | Omit scope when neither source provides it |
| `step-up-auth` | Handle 403 `insufficient_scope` → re-authorize |
| `retry-limits` | Don't infinitely retry 403 responses |

**Deferred until:** `www-authenticate-header.md` and `scope-challenge-handling.md` are completed.

---

## Gap Summary vs Conformance Suite

| Conformance Check ID | Pomerium Coverage | This Issue |
|---------------------|-------------------|------------|
| `token-endpoint-auth-method` | ❌ Not tested | Test #1 |
| `authorization-request` | ✅ Covered | - |
| `token-request` | ✅ Covered | - |
| `client-registration` | ✅ Covered | - |
| `prm-discovery` | ✅ Covered | - |
| `authorization-server-metadata` | ✅ Covered | - |
| `cimd-client-id-usage` | ✅ Covered | - |
| `scope-from-www-authenticate` | ❌ Not implemented | Deferred |
| `step-up-auth` | ❌ Not implemented | Deferred |
| PKCE validation errors | ❌ Not tested | Test #2 |
| Code replay protection | ❌ Not tested | Test #3 |
| Refresh token security | ❌ Not tested | Test #4 |
| Access token validation | ❌ Not tested | Test #5 |

---

## Implementation Tasks

- [ ] **Test #1:** `TestTokenEndpointClientSecretBasic` - 5 cases
- [ ] **Test #2:** `TestPKCECodeVerifierValidation` - 4 cases
- [ ] **Test #3:** `TestAuthorizationCodeReplayProtection` - 3 cases
- [ ] **Test #4:** `TestRefreshTokenSecurity` - 4 cases
- [ ] **Test #5:** `TestAccessTokenValidation` - 5 cases

### Test Helpers Needed

```go
// internal/mcp/e2e/helpers.go

// registerClientWithAuthMethod registers a client with the specified token_endpoint_auth_method
func registerClientWithAuthMethod(t *testing.T, env Environment, authMethod string) (clientID, clientSecret string)

// getAuthorizationCode completes auth flow and returns the code (for replay testing)
func getAuthorizationCode(t *testing.T, env Environment, clientID string) string

// exchangeCodeForTokens exchanges code for tokens, returns raw response for inspection
func exchangeCodeForTokens(t *testing.T, env Environment, code string, opts ...TokenRequestOption) (*http.Response, error)
```

---

## Acceptance Criteria

1. All 21 test cases pass
2. Error responses use OAuth 2.1 format (`{"error": "...", "error_description": "..."}`)
3. HTTP status codes match spec (400 for invalid_grant, 401 for invalid_client/unauthorized)
4. Tests are independent and can run in parallel
5. No flaky tests (deterministic timing, no race conditions)

---

## References

### MCP Specification
- [MCP Authorization](/.docs/mcp/basic/authorization.mdx)
- [MCP Security Best Practices](/.docs/mcp/basic/security_best_practices.mdx)

### OAuth Standards
- [OAuth 2.1 Draft](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750 - Bearer Token Usage](/.docs/RFC/rfc6750.txt)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9700 - OAuth Security BCP](/.docs/RFC/rfc9700.txt)

### Official Conformance Suite
- [GitHub: modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance)
- [Conformance Checks: client.ts](https://github.com/modelcontextprotocol/conformance/blob/main/src/checks/client.ts)
- [Auth Scenarios](https://github.com/modelcontextprotocol/conformance/tree/main/src/scenarios/client/auth)

---

## Log

- 2026-01-19: Issue created from conformance test gap analysis
- 2026-01-19: Expanded with detailed test scenarios and conformance suite links
- 2026-01-26: Reviewed - status confirmed open, tests still needed for security error handling paths
