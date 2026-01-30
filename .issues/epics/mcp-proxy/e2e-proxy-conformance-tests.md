---
id: e2e-proxy-conformance-tests
title: "E2E Proxy Conformance Tests"
status: open
created: 2026-01-26
updated: 2026-01-26
priority: high
labels:
  - mcp
  - proxy
  - testing
deps:
  - authorization-choreographer
  - request-transformation
  - upstream-token-lifecycle
---

# E2E Proxy Conformance Tests

## Summary

Implement comprehensive end-to-end tests for the MCP proxy functionality to verify correct behavior across the full authorization and request flow.

## Test Scenarios

### Basic Proxy Flow

1. **Happy Path - Full Authorization Flow**
   - MCP client sends request to Pomerium proxy route
   - No cached token → authorization flow initiated
   - User completes authorization with remote AS
   - Token acquired and cached
   - Request forwarded with upstream token
   - Response returned to client

2. **Cached Token Flow**
   - MCP client sends request
   - Valid cached token exists
   - Request forwarded immediately
   - No authorization flow triggered

3. **Token Refresh Flow**
   - MCP client sends request
   - Cached token is expiring
   - Token refreshed in background or inline
   - Request forwarded with new token

### Discovery Tests

4. **Protected Resource Metadata Discovery**
   - Upstream returns 401 with resource_metadata URL
   - Pomerium fetches and parses metadata
   - Authorization server identified

5. **AS Metadata Discovery**
   - Authorization server metadata fetched
   - Endpoints extracted correctly
   - PKCE support detected
   - CIMD support detected

6. **Discovery Fallback**
   - Primary discovery fails
   - Fallback to well-known URLs works

### Authorization Flow Tests

7. **PKCE Flow**
   - Code verifier generated correctly
   - Code challenge computed correctly
   - Token exchange includes code verifier

8. **State Parameter**
   - Random state generated
   - State validated on callback
   - Invalid state rejected

9. **CIMD Presentation**
   - CIMD URL used as client_id
   - Remote AS can fetch CIMD
   - CIMD contains correct redirect_uri

10. **Resource Indicator**
    - Resource parameter included in auth request
    - Resource parameter included in token request
    - Token audience validated

### Token Management Tests

11. **Per-User Token Isolation**
    - User A's token not accessible to User B
    - Same user shares token across sessions

12. **Per-Session Token Isolation**
    - Token isolated to single session
    - New session requires new token

13. **Token Revocation**
    - Tokens deleted on logout
    - Tokens deleted on session end
    - Tokens deleted on route removal

### Request Transformation Tests

14. **Token Replacement**
    - Pomerium token removed
    - Upstream token injected
    - Authorization header correct format

15. **Header Transformation**
    - Internal headers removed
    - Host header updated
    - Content preserved

### Error Handling Tests

16. **Upstream 401 Handling**
    - Token refresh attempted
    - Re-authorization if refresh fails
    - Eventual error if auth fails

17. **Upstream 403 Handling**
    - insufficient_scope triggers re-auth
    - Other 403 passed through

18. **Network Errors**
    - Timeout becomes 504
    - Connection failure becomes 502

### Security Tests

19. **Token Passthrough Prevention**
    - Pomerium token NEVER forwarded
    - Verify in all code paths

20. **Confused Deputy Prevention**
    - Token audience checked
    - Cross-route token use prevented

21. **CSRF Protection**
    - State parameter validated
    - Invalid state rejected
    - Expired state rejected

## Test Infrastructure

### Mock Remote MCP Server

```go
type MockMCPServer struct {
    // Returns 401 with WWW-Authenticate
    RequireAuth bool

    // Protected Resource Metadata
    ResourceMetadata *ProtectedResourceMetadata

    // Validates received tokens
    ExpectedAudience string
}
```

### Mock Remote Authorization Server

```go
type MockAuthorizationServer struct {
    // AS Metadata
    Metadata *ASMetadata

    // CIMD fetching
    FetchCIMDCalled bool
    ReceivedCIMDURL string

    // Token issuance
    IssuedTokens []TokenRecord
}
```

### Test Harness

```go
func TestMCPProxyE2E(t *testing.T) {
    // Start mock upstream MCP server
    mcpServer := NewMockMCPServer()

    // Start mock authorization server
    authServer := NewMockAuthorizationServer()

    // Configure Pomerium with proxy route
    pomerium := NewTestPomerium(t, WithProxyRoute(
        "https://test.pomerium.local",
        mcpServer.URL,
    ))

    // Create test MCP client
    client := NewTestMCPClient(pomerium.URL)

    // Execute test scenarios...
}
```

## Implementation Tasks

- [ ] Create mock MCP server with configurable auth behavior
- [ ] Create mock authorization server with CIMD support
- [ ] Implement test harness for proxy scenarios
- [ ] Write tests for all scenarios listed above
- [ ] Add tests for edge cases and error conditions
- [ ] Ensure tests run in CI/CD pipeline
- [ ] Add performance/load tests for token caching

## Acceptance Criteria

1. All test scenarios pass
2. Tests run in CI/CD pipeline
3. Test coverage for critical paths >90%
4. Security-critical paths have explicit tests
5. Tests are readable and maintainable
6. Mock servers are reusable

## References

- [MCP Proxy Epic](./index.md)
- [E2E Conformance Tests (MCP Epic)](../mcp/e2e-conformance-test-coverage.md)

## Log

- 2026-01-26: Issue created from epic breakdown
