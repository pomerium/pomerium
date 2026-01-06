---
id: mcp-refresh-token-and-session-lifecycle
title: "MCP Refresh Token Support and Session Lifecycle Integration"
status: open
created: 2026-01-06
updated: 2026-01-06
priority: critical
labels:
  - mcp
  - oauth2
  - session
  - pomerium-core
  - architecture
deps: []
---

# MCP Refresh Token Support and Session Lifecycle Integration

## Summary

This issue addresses a fundamental architectural gap: MCP access tokens are currently tied directly to Pomerium session expiration, but MCP clients expect OAuth 2.1-compliant refresh token flows for continuous session renewal. The solution requires implementing refresh tokens that can recreate or renew Pomerium sessions using stored upstream IdP refresh tokens.

## Problem Statement

### Current Architecture (Problematic)

```
MCP Client                      Pomerium MCP Handler                    Pomerium Session
     │                                  │                                     │
     ├─── Authorization Request ───────►│                                     │
     │                                  ├─── Create Session ─────────────────►│
     │                                  │                                     │
     │◄── Access Token (bound to ──────┤                                     │
     │    session.ExpiresAt)            │                                     │
     │                                  │                                     │
     ├─── API Request ─────────────────►│─── Validate Session ───────────────►│
     │                                  │                                     │
     │    ... time passes ...           │                                     │
     │                                  │                            Session Expires
     │                                  │                                     │
     ├─── API Request ─────────────────►│─── Session Invalid ────────────────►X
     │◄── 401 Unauthorized ─────────────┤                                     │
     │                                  │                                     │
     │    NO RECOVERY PATH              │                                     │
```

**Key Problems:**

1. **No Refresh Token Issued**: `handler_token.go` only returns `access_token`, no `refresh_token`:
   ```go
   resp := &oauth21proto.TokenResponse{
       AccessToken: accessToken,
       TokenType:   "Bearer",
       ExpiresIn:   proto.Int64(int64(expiresIn.Seconds())),
       // Missing: RefreshToken
   }
   ```

2. **Access Token = Session Lifetime**: Access token expiration is set to `session.ExpiresAt`:
   ```go
   accessToken, err := srv.GetAccessTokenForSession(session.Id, session.ExpiresAt.AsTime())
   ```

3. **Session Expiration Causes Hard Failure**: When Pomerium session expires (idle timeout, absolute timeout, IdP session expiry), MCP clients get 401 with no way to recover.

4. **Metadata Advertises Unsupported Grant**: `handler_metadata.go` claims `refresh_token` grant support but it's not implemented:
   ```go
   GrantTypesSupported: []string{"authorization_code", "refresh_token"},
   ```

### Expected Architecture (OAuth 2.1 / MCP Compliant)

```
MCP Client                      Pomerium MCP Handler                    Pomerium Session    Upstream IdP
     │                                  │                                     │                  │
     ├─── Authorization Request ───────►│                                     │                  │
     │                                  ├─── Create Session ─────────────────►│                  │
     │                                  │                                     │                  │
     │◄── Access Token (1hr) + ────────-┤                                     │                  │
     │    Refresh Token (30d)           │                                     │                  │
     │                                  │                                     │                  │
     ├─── API Request ─────────────────►│─── Validate Session ───────────────►│                  │
     │                                  │                                     │                  │
     │    ... access token expires ...  │                                     │                  │
     │                                  │                                     │                  │
     ├─── Refresh Token Request ───────►│                                     │                  │
     │                                  │─── Check Session ──────────────────►│                  │
     │                                  │    (expired)                        X                  │
     │                                  │                                                        │
     │                                  ├─── Refresh Upstream Token ────────────────────────────►│
     │                                  │◄── New IdP Tokens ─────────────────────────────────────┤
     │                                  │                                                        │
     │                                  ├─── Recreate Session ───────────────►│ (new)            │
     │                                  │                                     │                  │
     │◄── New Access Token + ──────────-┤                                     │                  │
     │    New Refresh Token             │                                     │                  │
```

## Pomerium Session Lifecycle Analysis

### Session Structure (`pkg/grpc/session/session.pb.go`)

```go
type Session struct {
    Id                   string                         // Session ID
    UserId               string                         // User ID
    IssuedAt             *timestamppb.Timestamp         // When session was created
    ExpiresAt            *timestamppb.Timestamp         // When session expires
    AccessedAt           *timestamppb.Timestamp         // Last access time
    IdToken              *IDToken                       // OIDC ID Token
    OauthToken           *OAuthToken                    // OAuth token (includes RefreshToken!)
    Claims               map[string]*structpb.ListValue // Session claims
    RefreshDisabled      bool                           // If true, session won't be refreshed
    IdpId                string                         // Identity Provider ID
}

type OAuthToken struct {
    AccessToken   string                 // Upstream IdP access token
    TokenType     string                 // Token type (Bearer)
    ExpiresAt     *timestamppb.Timestamp // Token expiration
    RefreshToken  string                 // Upstream IdP refresh token!
}
```

**Key Finding**: Pomerium sessions already store the upstream IdP's refresh token in `session.OauthToken.RefreshToken`. This is the key to implementing session renewal.

### Session Refresh Mechanism (`pkg/identity/manager/manager.go`)

The Identity Manager handles automatic session refresh:

```go
func (mgr *Manager) refreshSession(ctx context.Context, sessionID string) {
    s, u := mgr.dataStore.getSessionAndUser(sessionID)

    // Skip if session expired
    expiry := s.GetExpiresAt().AsTime()
    if !expiry.After(mgr.cfg.Load().now()) {
        mgr.deleteSession(ctx, sessionID)  // Session is deleted!
        return
    }

    // Skip if refresh disabled
    if s.GetRefreshDisabled() {
        return
    }

    // Skip if no OAuth token
    if s.GetOauthToken() == nil {
        return
    }

    // Refresh using upstream IdP
    newToken, err := authenticator.Refresh(ctx, FromOAuthToken(s.OauthToken), ...)
    if err != nil {
        mgr.deleteSession(ctx, sessionID)  // Session deleted on error
        return
    }

    s.OauthToken = ToOAuthToken(newToken)
    mgr.updateSession(ctx, s)
}
```

**Key Findings:**

1. **Expired sessions are deleted** - once a session expires, it's removed from databroker
2. **RefreshDisabled prevents refresh** - some sessions (e.g., created from access tokens) have `RefreshDisabled = true`
3. **Refresh uses stored upstream refresh token** - the mechanism exists!
4. **Refresh failures delete the session** - no partial state

### Session Expiration Triggers

Sessions can expire due to:

1. **Absolute Timeout**: `session.ExpiresAt` reached (configured via `CookieExpire`)
2. **Idle Timeout**: No recent access (not currently implemented in core Pomerium)
3. **IdP Token Expiry**: When upstream tokens can't be refreshed
4. **Manual Revocation**: User signs out or admin revokes
5. **Policy Change**: Route policy changes can invalidate sessions

### MCP Token to Session Binding

Currently in `handler_token.go`:

```go
// MCP access token is created from session ID and session expiration
accessToken, err := srv.GetAccessTokenForSession(session.Id, session.ExpiresAt.AsTime())

// Access token is just encrypted session ID with expiration
func (srv *Handler) GetAccessTokenForSession(sessionID string, sessionExpiresAt time.Time) (string, error) {
    return CreateCode(CodeTypeAccess, sessionID, sessionExpiresAt, "", srv.cipher)
}
```

The MCP access token is essentially an encrypted reference to a Pomerium session, with the same expiration. When the session expires or is deleted, the access token becomes invalid.

## Proposed Solution: Session Renewal on Refresh

When an MCP client presents a refresh token:
1. Validate the refresh token
2. Check if the associated Pomerium session still exists
3. If session exists and is valid, issue new access token
4. If session expired but can be renewed (upstream refresh token exists):
   - Use the stored upstream IdP refresh token to get new IdP tokens
   - Create a new Pomerium session from the refreshed IdP tokens
   - Issue new MCP access token bound to new session
5. If session cannot be renewed, return `invalid_grant` error

### Why Option 2?

| Consideration | Option 1 (Independent) | Option 2 (Renewal) | Option 3 (Extended) | Option 4 (Hybrid) |
|---------------|------------------------|-------------------|---------------------|-------------------|
| Session Control | ❌ Bypasses controls | ✅ Maintains controls | ⚠️ Delayed controls | ✅ Maintains controls |
| Implementation | Medium | Complex | Simple | Complex |
| Security | ⚠️ Risk of bypass | ✅ Proper validation | ✅ Standard | ✅ Proper validation |
| User Experience | ✅ Seamless | ✅ Seamless | ⚠️ Eventually fails | ✅ Seamless |
| Policy Enforcement | ❌ Stale policies | ✅ Current policies | ⚠️ Delayed | ✅ Current policies |

**Option 2 is preferred** because:
- Maintains Pomerium's session control and policy enforcement
- Uses existing upstream refresh token infrastructure
- Doesn't create a separate identity/session system
- Aligns with how the Identity Manager already works

## Implementation Design

### 1. MCP Refresh Token Structure

```go
type MCPRefreshToken struct {
    ID               string    // Unique refresh token ID
    SessionID        string    // Original Pomerium session ID (may be expired)
    UserID           string    // User ID
    ClientID         string    // MCP client ID
    UpstreamTokenID  string    // Reference to stored upstream OAuth2 token
    IssuedAt         time.Time // When refresh token was issued
    ExpiresAt        time.Time // Refresh token expiration (e.g., 30 days)
    RotationCounter  int       // For rotation tracking
    Scope            []string  // Granted scopes
    IdpId            string    // Identity Provider ID
}
```

### 2. Storage Schema

Add to `storage.go`:

```go
// MCP-specific refresh token (separate from session)
type MCPRefreshTokenRecord struct {
    proto.Message
    Id               string
    OriginalSession  string    // Original session ID
    UserId           string
    ClientId         string
    IdpId            string
    UpstreamRefresh  string    // Encrypted upstream refresh token
    IssuedAt         *timestamppb.Timestamp
    ExpiresAt        *timestamppb.Timestamp
    Revoked          bool
    RotationCount    int32
    Scope            []string
}
```

### 3. Token Issuance Flow

Modify `handler_token.go`:

```go
func (srv *Handler) handleAuthorizationCodeToken(...) {
    // ... existing validation ...

    session, err := srv.storage.GetSession(ctx, authReq.SessionId)

    // Generate short-lived access token (1 hour)
    accessTokenExpiry := time.Now().Add(1 * time.Hour)
    if session.ExpiresAt.AsTime().Before(accessTokenExpiry) {
        accessTokenExpiry = session.ExpiresAt.AsTime()
    }
    accessToken, _ := srv.GetAccessTokenForSession(session.Id, accessTokenExpiry)

    // Generate long-lived refresh token (30 days)
    refreshToken, _ := srv.CreateMCPRefreshToken(ctx, MCPRefreshTokenParams{
        SessionID:       session.Id,
        UserID:          session.UserId,
        ClientID:        *tokenReq.ClientId,
        IdpId:           session.IdpId,
        UpstreamRefresh: session.OauthToken.RefreshToken,
        ExpiresIn:       30 * 24 * time.Hour,
        Scope:           authReq.GetScope(),
    })

    resp := &oauth21proto.TokenResponse{
        AccessToken:  accessToken,
        TokenType:    "Bearer",
        ExpiresIn:    proto.Int64(int64(time.Until(accessTokenExpiry).Seconds())),
        RefreshToken: refreshToken,
        Scope:        strings.Join(authReq.GetScope(), " "),
    }
}
```

### 4. Refresh Token Grant Flow

Add to `handler_token.go`:

```go
func (srv *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, tokenReq *oauth21proto.TokenRequest) {
    ctx := r.Context()

    // 1. Validate refresh token
    refreshTokenRecord, err := srv.storage.GetMCPRefreshToken(ctx, tokenReq.GetRefreshToken())
    if err != nil {
        oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
        return
    }

    // 2. Check refresh token expiration
    if refreshTokenRecord.ExpiresAt.AsTime().Before(time.Now()) {
        oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
        return
    }

    // 3. Check if revoked
    if refreshTokenRecord.Revoked {
        // Potential token theft - revoke all tokens in family
        srv.revokeMCPTokenFamily(ctx, refreshTokenRecord.UserId, refreshTokenRecord.ClientId)
        oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
        return
    }

    // 4. Try to get existing session
    session, err := srv.storage.GetSession(ctx, refreshTokenRecord.OriginalSession)

    var newSession *session.Session
    if err == nil && session.ExpiresAt.AsTime().After(time.Now()) {
        // Session still valid - use it
        newSession = session
    } else {
        // Session expired or not found - try to recreate
        newSession, err = srv.recreateSessionFromRefreshToken(ctx, refreshTokenRecord)
        if err != nil {
            log.Ctx(ctx).Error().Err(err).Msg("failed to recreate session")
            oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
            return
        }
    }

    // 5. Issue new tokens
    accessToken, _ := srv.GetAccessTokenForSession(newSession.Id, time.Now().Add(1*time.Hour))

    // 6. Rotate refresh token (for public clients)
    newRefreshToken, _ := srv.RotateMCPRefreshToken(ctx, refreshTokenRecord, newSession.Id)

    resp := &oauth21proto.TokenResponse{
        AccessToken:  accessToken,
        TokenType:    "Bearer",
        ExpiresIn:    proto.Int64(3600),
        RefreshToken: newRefreshToken,
        Scope:        strings.Join(refreshTokenRecord.Scope, " "),
    }

    // ... write response ...
}
```

### 5. Session Recreation

```go
func (srv *Handler) recreateSessionFromRefreshToken(
    ctx context.Context,
    refreshRecord *MCPRefreshTokenRecord,
) (*session.Session, error) {
    // 1. Get authenticator for the IdP
    authenticator, err := srv.getAuthenticator(ctx, refreshRecord.IdpId)
    if err != nil {
        return nil, fmt.Errorf("no authenticator for IdP: %w", err)
    }

    // 2. Create OAuth2 token from stored refresh token
    oldToken := &oauth2.Token{
        RefreshToken: refreshRecord.UpstreamRefresh,
    }

    // 3. Refresh the upstream token
    newToken, err := authenticator.Refresh(ctx, oldToken, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to refresh upstream token: %w", err)
    }

    // 4. Create new session
    newSession := &session.Session{
        Id:        uuid.NewString(),
        UserId:    refreshRecord.UserId,
        IdpId:     refreshRecord.IdpId,
        IssuedAt:  timestamppb.Now(),
        ExpiresAt: timestamppb.New(time.Now().Add(srv.sessionLifetime)),
        OauthToken: &session.OAuthToken{
            AccessToken:  newToken.AccessToken,
            RefreshToken: newToken.RefreshToken,
            TokenType:    newToken.TokenType,
            ExpiresAt:    timestamppb.New(newToken.Expiry),
        },
    }

    // 5. Update user info
    authenticator.UpdateUserInfo(ctx, newToken, newSession)

    // 6. Store new session
    err = srv.storage.PutSession(ctx, newSession)
    if err != nil {
        return nil, fmt.Errorf("failed to store new session: %w", err)
    }

    // 7. Update refresh token with new session reference and upstream token
    refreshRecord.OriginalSession = newSession.Id
    refreshRecord.UpstreamRefresh = newToken.RefreshToken
    srv.storage.UpdateMCPRefreshToken(ctx, refreshRecord)

    return newSession, nil
}
```

## Implementation Tasks

### Phase 1: Foundation
- [ ] Create `MCPRefreshTokenRecord` protobuf message
- [ ] Add refresh token storage methods to `storage.go`
- [ ] Generate protobuf code
- [ ] Add refresh token encryption/decryption utilities

### Phase 2: Token Issuance
- [ ] Modify `handleAuthorizationCodeToken` to issue refresh tokens
- [ ] Add short-lived access token expiry (1 hour default)
- [ ] Store refresh token with upstream refresh token reference
- [ ] Add configuration for token lifetimes

### Phase 3: Refresh Grant
- [ ] Implement `handleRefreshTokenGrant` in `handler_token.go`
- [ ] Add `refresh_token` case to Token switch statement
- [ ] Implement refresh token validation
- [ ] Implement refresh token rotation for public clients

### Phase 4: Session Recreation
- [ ] Implement `recreateSessionFromRefreshToken`
- [ ] Integrate with Identity Manager's authenticator infrastructure
- [ ] Handle upstream token refresh errors
- [ ] Create new Pomerium session from refreshed tokens

### Phase 5: Security & Cleanup
- [ ] Implement refresh token revocation
- [ ] Implement token family revocation (theft detection)
- [ ] Add refresh token cleanup job
- [ ] Ensure session revocation invalidates MCP tokens

### Phase 6: Testing
- [ ] Unit tests for refresh token flow
- [ ] Integration tests for session recreation
- [ ] Test upstream refresh token failures
- [ ] Test token rotation
- [ ] Test revocation propagation

## Configuration Options

```yaml
mcp:
  access_token_lifetime: 1h       # Short-lived access tokens
  refresh_token_lifetime: 720h    # 30 days
  rotate_refresh_tokens: true     # Required for public clients
  session_recreation_enabled: true
```

## Security Considerations

### Refresh Token Storage Security
- Refresh tokens stored encrypted in databroker
- Upstream refresh tokens encrypted with Pomerium shared secret
- Separate encryption from session storage

### Rotation for Public Clients
Per OAuth 2.1, public clients MUST use refresh token rotation:
- Each refresh token use issues a new refresh token
- Old refresh token is invalidated
- Reuse of old token indicates potential theft → revoke all tokens

### Policy Enforcement
When recreating sessions:
- Re-validate user against current policies
- Check if IdP account is still valid (via refresh)
- Do NOT bypass any authorization checks

### Revocation Propagation
- Session revocation must invalidate all associated MCP refresh tokens
- User logout must invalidate all MCP tokens
- Admin revocation must cascade to MCP tokens

## Acceptance Criteria

1. ✅ Token endpoint returns `refresh_token` alongside `access_token`
2. ✅ Access tokens have short lifetime (configurable, default 1 hour)
3. ✅ Refresh tokens have long lifetime (configurable, default 30 days)
4. ✅ Token endpoint accepts `grant_type=refresh_token`
5. ✅ Refresh token use extends MCP session without user interaction
6. ✅ Session recreation works when Pomerium session has expired
7. ✅ Session recreation fails gracefully when upstream refresh fails
8. ✅ Refresh token rotation works for public clients
9. ✅ Token revocation cascades properly
10. ✅ Security controls (policies) are enforced on session recreation
11. ✅ MCP clients can maintain long-running connections (days/weeks)

## Related Files

| File | Purpose |
|------|---------|
| `internal/mcp/handler_token.go` | Token endpoint - main implementation target |
| `internal/mcp/storage.go` | Add refresh token storage |
| `internal/mcp/handler_metadata.go` | Already advertises refresh_token support |
| `internal/mcp/token.go` | Token generation utilities |
| `pkg/identity/manager/manager.go` | Session refresh mechanics (reference) |
| `pkg/grpc/session/session.proto` | Session structure |
| `authenticate/identity.go` | Identity provider integration |

## References

- [OAuth 2.1 Draft (draft-ietf-oauth-v2-1-13)](/.docs/RFC/draft-ietf-oauth-v2-1.txt)
  - Section 1.3.2 - Refresh Token
  - Section 4.3.1 - Token Endpoint Extension
- [RFC 9700 - OAuth 2.0 Security Best Current Practice](/.docs/RFC/rfc9700.txt)
  - Section 2.2.2 - Refresh Tokens
  - Section 4.14 - Refresh Token Protection
- [RFC 6750 - Bearer Token Usage](/.docs/RFC/rfc6750.txt)
- [MCP Authorization](/.docs/mcp/basic/authorization.mdx)

## Log

- 2026-01-06: Issue created - comprehensive analysis of session lifecycle integration
- 2026-01-06: Merged with refresh-token-support for complete solution
