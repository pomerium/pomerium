# PR Series: MCP Upstream OAuth + Service Accounts → main

## Status

| Category | Count | Details |
|----------|-------|---------|
| **Merged** | 15 | Foundation PRs (#6088, #6091, #6099, #6100, #6107, #6109, #6114, #6118, #6119, #6121) + #6130, #6133, #6137, #6144, #6145 |
| **Remaining** | 10 | PRs 1–10 below |

## Summary

The `mcp-service-accounts` branch implements **upstream MCP OAuth handling via Envoy ext_proc** and **service account support for non-interactive MCP clients**.

When an upstream MCP server returns 401/403, Pomerium intercepts it via ext_proc, runs RFC 9728 PRM discovery, performs client registration (CIMD/DCR), and orchestrates the OAuth flow so the MCP client gets a token. Service accounts enable autonomous agents to reuse upstream tokens provisioned by interactive user flows.

---

## Merged PRs

| PR | Linear | Title | What it established |
|----|--------|-------|---------------------|
| [#6088](https://github.com/pomerium/pomerium/pull/6088) | [ENG-3525](https://linear.app/pomerium/issue/ENG-3525) | mcp: host Client ID Metadata Documents for auto-discovery mode | CIMD endpoint for MCP clients |
| [#6091](https://github.com/pomerium/pomerium/pull/6091) | [ENG-3528](https://linear.app/pomerium/issue/ENG-3528) | mcp: add ext_proc integration for response interception | ext_proc server scaffold, Envoy filter chain |
| [#6099](https://github.com/pomerium/pomerium/pull/6099) | [ENG-3555](https://linear.app/pomerium/issue/ENG-3555) | mcp: add upstream OAuth discovery core functions (RFC 9728/8414) | `runDiscovery()`, PRM + AS metadata fetching |
| [#6100](https://github.com/pomerium/pomerium/pull/6100) | [ENG-3556](https://linear.app/pomerium/issue/ENG-3556) | mcp: add upstream MCP token storage | Token CRUD, singleflight refresh |
| [#6107](https://github.com/pomerium/pomerium/pull/6107) | [ENG-3572](https://linear.app/pomerium/issue/ENG-3572) | mcp: add UpstreamOAuthClient type and storage for DCR caching | Client registration caching |
| [#6109](https://github.com/pomerium/pomerium/pull/6109) | [ENG-3570](https://linear.app/pomerium/issue/ENG-3570) | fix(mcp): CORS header consistency and e2e tests | CORS fixes, e2e test harness |
| [#6114](https://github.com/pomerium/pomerium/pull/6114) | — | databroker: add CompositeRecordID utility | Record ID builder for indexed lookups |
| [#6118](https://github.com/pomerium/pomerium/pull/6118) | [ENG-3589](https://linear.app/pomerium/issue/ENG-3589) | mcp: add PendingUpstreamAuth proto and storage methods | `PendingUpstreamAuth` protobuf + CRUD |
| [#6119](https://github.com/pomerium/pomerium/pull/6119) | [ENG-3590](https://linear.app/pomerium/issue/ENG-3590) | mcp: pass upstream host via route context metadata and extend HostInfo | Route context metadata + `UpstreamURL` in HostInfo |
| [#6121](https://github.com/pomerium/pomerium/pull/6121) | [ENG-3600](https://linear.app/pomerium/issue/ENG-3600) | databroker: add first-class record auto-expiry via Options TTL | `Options.Ttl` for auto-expiring records |
| [#6130](https://github.com/pomerium/pomerium/pull/6130) | [ENG-3591](https://linear.app/pomerium/issue/ENG-3591) | mcp: add ext_proc handler interface for upstream token injection | `UpstreamRequestHandler` interface, request/response handling in ext_proc |
| [#6133](https://github.com/pomerium/pomerium/pull/6133) | [ENG-3592](https://linear.app/pomerium/issue/ENG-3592) | mcp: add upstream OAuth setup utilities and token exchange | `runUpstreamOAuthSetup()`, `exchangeToken()`, discovery, PKCE, URL helpers |
| [#6137](https://github.com/pomerium/pomerium/pull/6137) | — | docs: add MCP proxying architecture design document | DESIGN.md |
| [#6144](https://github.com/pomerium/pomerium/pull/6144) | [ENG-3650](https://linear.app/pomerium/issue/ENG-3650) | feat: add SSRF-safe HTTP client for MCP metadata fetching | SSRF protection, `DomainMatcher`, `MCPAllowedASMetadataDomains` config |
| [#6145](https://github.com/pomerium/pomerium/pull/6145) | [ENG-3654](https://linear.app/pomerium/issue/ENG-3654) | feat: add DCR for upstream OAuth | `UpstreamOAuthClient` storage, `HandlerStorage` export, DCR caching |

---

## Remaining PRs (10 PRs, ordered by dependency)

### PR 1: Discovery enhancements — PRM origin fallback + DCR fallback option
**Files (~250 lines):**
- `internal/mcp/upstream_oauth_setup.go` (+92 — `WithAllowDCRFallback()`, `WithAllowPRMSameDomainOrigin()`, `runDiscoveryWithOptions()`, `originOf()`, `RegistrationEndpoint` + `ClientSecret` in results, DCR fallback logic in `runUpstreamOAuthSetup`)
- `internal/mcp/upstream_oauth_setup_test.go` (+80 — PRM origin validation tests, DCR fallback tests)
- `config/runtime_flags.go` (+6 — `RuntimeFlagMCPAllowPRMSameDomainOrigin`)

**What it does:**
- Adds relaxed PRM resource validation: when exact `normalizeResourceURL()` match fails, falls back to same-origin (scheme+host+port) match via `originOf()`, gated by `RuntimeFlagMCPAllowPRMSameDomainOrigin` (default: true). Helps with providers publishing origin-level PRM resources for subpath endpoints.
- Adds `WithAllowDCRFallback(true)` option: when upstream AS does not support `client_id_metadata_document`, allows `runUpstreamOAuthSetup` to return empty `ClientID` with `RegistrationEndpoint` populated, so callers can fall back to RFC 7591 DCR.
- Propagates `RegistrationEndpoint` from AS metadata through `discoveryResult`.

**Depends on:** #6133 (merged)
**Base branch:** `main`

---

### PR 2: Config + proto additions for upstream auth
**Files (~100 lines non-generated):**
- `internal/oauth21/proto/pending_upstream_auth.proto` (+7 — `resource_param` field 19)
- `internal/oauth21/proto/upstream_mcp_token.proto` (+5 — `resource_param` field 14)
- `config/policy.go` (+11 — `AuthorizationServerURL` on `MCPServer` + getter)
- `config/custom.go` (+4 — PB conversion for `AuthorizationServerURL`)
- `pkg/grpc/config/config.proto` (+1 — `authorization_server_url` field on `MCPServer`)
- `internal/mcp/host_info.go` (+28 — `AuthorizationServerURL` field on `ServerHostInfo` + population from policy)
- `authorize/route_context_metadata_test.go` (+23 — upstream_host test coverage)

**What it does:**
- Adds `resource_param` to `PendingUpstreamAuth` and `UpstreamMCPToken` protos for consistent RFC 8707 resource indicators across auth + token refresh.
- Adds `AuthorizationServerURL` config option for MCP server routes — used as AS issuer fallback when PRM discovery fails.
- Extends `ServerHostInfo` with `AuthorizationServerURL` populated from policy.

**Depends on:** none (parallel with PR 1)
**Base branch:** `main`

---

### PR 3: UpstreamAuthHandler — token injection + session identity
**Files (~600 lines):**
- `internal/mcp/upstream_auth.go` (NEW, ~380 lines — struct, constructors, `GetUpstreamToken()`, `getStaticUpstreamOAuth2Token()`, `getAutoDiscoveryToken()`, `refreshToken()`, `getSessionIdentity()` session-only, helpers)
- `internal/mcp/upstream_auth_test.go` (NEW, ~450 lines — `TestRefreshToken_ResourceParam`, `TestHandleUpstreamResponse_DownstreamHostRouting` token injection subtests)
- `internal/mcp/DESIGN.md` (+17 — error handling flowchart update)

**What it does:**
- `UpstreamAuthHandler` struct: implements `extproc.UpstreamRequestHandler`
- `GetUpstreamToken()`: lookup cached token → route to static or auto-discovery path
  - `getStaticUpstreamOAuth2Token()`: singleflight token fetch for `upstream_oauth2` config routes
  - `getAutoDiscoveryToken()`: cached MCP token lookup + inline refresh if expired
- `refreshToken()`: token refresh with consistent RFC 8707 `resource` parameter
- `getSessionIdentity()`: resolves user ID from sessions only (SA fallback added in PR 4)
- `HandleUpstreamResponse()`: stub that dispatches to `handle401()` (minimal — returns nil/error for now)
- `handle401()`: calls `runUpstreamOAuthSetup()` → generates PKCE → stores pending auth → returns 401 action. Session-only, no DCR (requires client_id from CIMD).

**Depends on:** PR 1, PR 2
**Base branch:** Blocked — requires PRs 1+2 to merge first

---

### PR 4: Service account support for upstream auth
**Files (~300 lines):**
- `internal/mcp/upstream_auth.go` (+50 — SA fallback in `getSessionIdentity()`, SA pass-through in `handle401()`)
- `internal/mcp/storage.go` (+7 — `GetServiceAccount()` on `HandlerStorage` interface + implementation)
- `internal/mcp/upstream_auth_test.go` (+200 — `TestServiceAccountSupport` full section)

**What it does:**
- `getSessionIdentity()` falls back from sessions to service accounts via `storage.GetServiceAccount()` when session lookup returns NotFound
- Validates service account expiry via `sa.Validate()`
- `handle401()` detects service accounts (`identity.IsServiceAccount`) and passes through upstream 401 unchanged — no interactive OAuth for non-interactive clients
- Token paths use `sessionIdentity.UserID`, enabling service accounts to share upstream tokens provisioned by interactive users (same cache key: `user_id + route_id + upstream_server`)

**Depends on:** PR 3
**Base branch:** Blocked — requires PR 3 to merge first

---

### PR 5: Proactive DCR in UpstreamAuthHandler
**Files (~250 lines):**
- `internal/mcp/upstream_auth.go` (+140 — `getOrRegisterUpstreamOAuthClient()`, `registerWithUpstreamAS()`, DCR integration in `handle401()`)
- `internal/mcp/upstream_auth_test.go` (+100 — `TestHandle401_ClientRegistrationStrategy` CIMD vs DCR tests)

**What it does:**
- When `runUpstreamOAuthSetup()` returns empty `ClientID` (AS doesn't support CIMD), `handle401()` falls back to DCR via `getOrRegisterUpstreamOAuthClient()`.
- `getOrRegisterUpstreamOAuthClient()`: check cached client → singleflight DCR → store result
- `registerWithUpstreamAS()`: RFC 7591 registration request to upstream AS registration endpoint
- Stores `client_secret` in `PendingUpstreamAuth` for non-public DCR clients

**Depends on:** PR 4
**Base branch:** Blocked — requires PR 4 to merge first

---

### PR 6: Controlplane wiring + authorize evaluator cleanup
**Files (~150 lines):**
- `internal/controlplane/server.go` (+15 — `WithExtProcHandler()`, auto-create `UpstreamAuthHandler`, pass to ext_proc)
- `authorize/evaluator/headers_evaluator_evaluation.go` (+5/−13 — remove `GetUpstreamOAuth2Token()`, strip Authorization for all MCP server routes)
- `authorize/evaluator/headers_evaluator_test.go` (+28/−46 — updated tests for header stripping)
- `authorize/internal/store/store.go` (+2/−6 — remove `GetUpstreamOAuth2Token()` from `MCPAccessTokenProvider`)

**What it does:**
- **Controlplane**: wires `UpstreamAuthHandler` into ext_proc server when MCP runtime flag is set. Graceful degradation: logs warning if handler creation fails.
- **Evaluator cleanup**: removes upstream token injection from authorize path — ext_proc is now sole source. All MCP server routes strip Authorization header.

**Why combined:** The evaluator cleanup is only safe after ext_proc is wired to inject tokens. Combining ensures no gap.

**Depends on:** PR 5 (handler must exist with full capability)
**Base branch:** Blocked — requires PR 5 to merge first

---

### PR 7: OAuth callback handler
**Files (~250 lines):**
- `internal/mcp/handler_client_oauth_callback.go` (NEW, 191 lines)
- `internal/mcp/handler.go` (+54/−54 — replace `ClientOAuthCallbackStub` with real handler, add `WithHTTPClient()`, wire `httpClient`, `asMetadataDomainMatcher`, `allowPRMSameDomainOrigin` fields)

**What it does:**
- `ClientOAuthCallback()`: receives auth code + state from upstream AS → validates pending auth state (expiry, PKCE) → exchanges code for tokens → stores `UpstreamMCPToken` → cleans up pending state → completes MCP auth flow via `AuthorizationResponse()` or redirects to original URL
- Conditional `client_secret` inclusion (public CIMD clients skip it)
- RFC 8707 `resource` parameter with fallback to `upstream_server`
- Handler wiring: replaces stub, adds new fields to `Handler` struct

**Depends on:** PR 6 (ext_proc must be active for end-to-end flow)
**Base branch:** Blocked — requires PR 6 to merge first

---

### PR 8: handler_connect dual-path + handler_list_routes + handler_authorization
**Files (~600 lines):**
- `internal/mcp/handler_connect.go` (+490/−73 — dual-path refactoring, `resolveAutoDiscoveryAuth()`, `getOrRegisterUpstreamOAuthClient()`, `registerWithUpstreamAS()`, port-stripping bugfix)
- `internal/mcp/handler_list_routes.go` (+36/−18 — auto-discovery route filtering, token expiry validation)
- `internal/mcp/handler_authorization.go` (+42 — auto-discovery upstream OAuth in Authorize endpoint)

**What it does:**
- **handler_connect**: refactored from single-path to dual-path design:
  1. Static `upstream_oauth2` config path: existing flow (check token → AuthorizationRequest → redirect to login)
  2. Auto-discovery path: check cached MCP token → `resolveAutoDiscoveryAuth()` → redirect to upstream AS or back to client
  - Includes proactive DCR: when `runUpstreamOAuthSetup()` returns empty ClientID, calls `getOrRegisterUpstreamOAuthClient()` for RFC 7591 registration
  - Fix: `checkClientRedirectURL()` uses `stripPort()` (port validation bug)
- **handler_list_routes**: reports `NeedsOauth: true` for all MCP server routes; checks appropriate token store per route type
- **handler_authorization**: proactive auto-discovery — checks upstream PRM → creates pending auth → redirects to upstream AS in single round-trip

**Depends on:** PR 7 (callback must be wired for connect flow to complete)
**Base branch:** Blocked — requires PR 7 to merge first

---

### PR 9: Unit tests — review findings + resource_param coverage
**Files (~850 lines):**
- `internal/mcp/handler_review_findings_test.go` (NEW, 677 lines)
- `internal/mcp/upstream_auth_test.go` (+180 — `TestHandle401_ResourceParamStoredInPending`, `TestReusePendingAuth_ResourceParamConsistency`)

**What it does:**
- **Review findings tests**: comprehensive coverage for edge cases — authorization flow variants, handler_connect dual-path logic, token refresh/expiry, error handling, session/service account handling, pending auth cleanup
- **Resource param tests**: validates `resource_param` stored correctly in pending auth (origin for fallback discovery), and consistency across auth reuse

**Depends on:** PR 8 (all behavior must be in place)
**Base branch:** Blocked — requires PR 8 to merge first

---

### PR 10: E2E tests
**Files (~1,130 lines):**
- `internal/mcp/e2e/mcp_client_routes_test.go` (NEW, 336 lines)
- `internal/mcp/e2e/mcp_upstream_dcr_fallback_test.go` (NEW, 309 lines)
- `internal/mcp/e2e/service_account_test.go` (NEW, 489 lines)

**What it does:**
- **MCP client routes e2e**: integration tests for `GET /.pomerium/mcp/routes`, `GET /.pomerium/mcp/connect`, `POST /.pomerium/mcp/routes/disconnect` — validates dual-path logic with real HTTP flows
- **DCR fallback e2e**: integration test for the full PRM origin fallback + proactive DCR flow with a mock upstream AS
- **Service account e2e**: integration test for service account identity resolution, token sharing, and 401 pass-through

**Depends on:** PR 9 (all behavior + unit tests in place)
**Base branch:** Blocked — requires PR 9 to merge first

---

## Dependency Graph

```
  (all merged into main)
  #6130 (ext_proc interface) ──────┐
  #6133 (setup utilities) ─────────┤  ← MERGED
  #6144 (SSRF-safe client) ────────┤
  #6145 (DCR for upstream) ────────┤
                                   ↓
   PR 1 (discovery enhancements, ~250 lines) ──┐
   PR 2 (config + proto additions, ~100 lines) ─┤  ← PARALLEL, open now
                                                ↓
   PR 3 (UpstreamAuthHandler token injection, ~600 lines)
                                                ↓
   PR 4 (service account support, ~300 lines)
                                                ↓
   PR 5 (proactive DCR in UpstreamAuthHandler, ~250 lines)
                                                ↓
   PR 6 (controlplane wiring + evaluator cleanup, ~150 lines)
                                                ↓
   PR 7 (OAuth callback handler, ~250 lines)
                                                ↓
   PR 8 (handler_connect + list_routes + authorization, ~600 lines)
                                                ↓
   PR 9 (review findings + resource_param tests, ~850 lines)
                                                ↓
   PR 10 (e2e tests, ~1,130 lines)
```

**Next PRs to open:** PR 1 and PR 2 in parallel, both targeting `main`.

---

## Size Estimates

| PR | Lines | Files | Complexity | Review focus |
|----|-------|-------|------------|--------------|
| 1 | ~250 | 3 | Medium | PRM origin validation relaxation, DCR fallback semantics |
| 2 | ~100 | 7 | Low | Data model additions only, no behavior |
| 3 | ~600 | 3 | Medium | Singleflight keying, token refresh, resource param handling |
| 4 | ~300 | 3 | Low-Medium | Session→SA fallback, 401 pass-through, token sharing |
| 5 | ~250 | 2 | Medium | DCR singleflight, RFC 7591 registration, secret handling |
| 6 | ~150 | 4 | Low-Medium | Wiring correctness, evaluator removal safety |
| 7 | ~250 | 2 | Medium | Callback security (state/PKCE validation), pending auth lifecycle |
| 8 | ~600 | 3 | Medium | Dual-path logic, DCR in Handler, port-stripping bugfix |
| 9 | ~850 | 2 | Low | Pure tests |
| 10 | ~1,130 | 3 | Low | Pure e2e tests |

## Build/Test Considerations

- Each PR should compile independently (`make build`)
- PR 1 and PR 2 are parallel — no interdependency, both target `main`
- PR 3 introduces `UpstreamAuthHandler` with session-only identity and CIMD-only client registration
- PR 4 adds service account fallback — additive, doesn't change existing session behavior
- PR 5 adds DCR fallback — additive, only activates when CIMD is unsupported
- PR 6 activates ext_proc token injection AND removes authorize token injection in the same PR (no gap)
- PR 7 wires the OAuth callback — completes the upstream OAuth code exchange flow
- PR 8 enables client-facing endpoints for auto-discovery routes, including DCR in the connect handler
- PRs 9–10 are pure test additions — can serve as final validation

## Linear Ticket ↔ PR Cross-Reference

| Linear Ticket | Title | PR | Status |
|---------------|-------|----|--------|
| [ENG-3525](https://linear.app/pomerium/issue/ENG-3525) | Host CIMD for auto-discovery mode | [#6088](https://github.com/pomerium/pomerium/pull/6088) | Merged |
| [ENG-3528](https://linear.app/pomerium/issue/ENG-3528) | ext_proc scaffolding for response interception | [#6091](https://github.com/pomerium/pomerium/pull/6091) | Merged |
| [ENG-3555](https://linear.app/pomerium/issue/ENG-3555) | Upstream OAuth discovery (RFC 9728/8414) | [#6099](https://github.com/pomerium/pomerium/pull/6099) | Merged |
| [ENG-3556](https://linear.app/pomerium/issue/ENG-3556) | Upstream MCP token storage | [#6100](https://github.com/pomerium/pomerium/pull/6100) | Merged |
| [ENG-3570](https://linear.app/pomerium/issue/ENG-3570) | Bug: mcp-inspector connect issue | [#6109](https://github.com/pomerium/pomerium/pull/6109) | Merged |
| [ENG-3572](https://linear.app/pomerium/issue/ENG-3572) | Cache DCR client registrations | [#6107](https://github.com/pomerium/pomerium/pull/6107) | Merged |
| [ENG-3589](https://linear.app/pomerium/issue/ENG-3589) | PendingUpstreamAuth state storage | [#6118](https://github.com/pomerium/pomerium/pull/6118) | Merged |
| [ENG-3590](https://linear.app/pomerium/issue/ENG-3590) | Upstream host metadata + HostInfo | [#6119](https://github.com/pomerium/pomerium/pull/6119) | Merged |
| [ENG-3591](https://linear.app/pomerium/issue/ENG-3591) | ext_proc token injection + 401/403 interception | [#6130](https://github.com/pomerium/pomerium/pull/6130) | Merged |
| [ENG-3592](https://linear.app/pomerium/issue/ENG-3592) | Upstream OAuth setup + UpstreamAuthHandler | [#6133](https://github.com/pomerium/pomerium/pull/6133) + PRs 1,3 | Partially merged |
| [ENG-3595](https://linear.app/pomerium/issue/ENG-3595) | Validate single upstream target per MCP route | Standalone | In QA |
| [ENG-3600](https://linear.app/pomerium/issue/ENG-3600) | Databroker record auto-expiry via TTL | [#6121](https://github.com/pomerium/pomerium/pull/6121) | Merged |
| [ENG-3650](https://linear.app/pomerium/issue/ENG-3650) | SSRF-safe AS metadata domain validation | [#6144](https://github.com/pomerium/pomerium/pull/6144) | Merged |
| [ENG-3654](https://linear.app/pomerium/issue/ENG-3654) | RFC 7591 DCR for upstream OAuth | [#6145](https://github.com/pomerium/pomerium/pull/6145) | Merged |
| [ENG-3666](https://linear.app/pomerium/issue/ENG-3666) | Service account support for MCP routes | PR 4 | In Progress |
| [ENG-3593](https://linear.app/pomerium/issue/ENG-3593) | OAuth callback + authorize auto-discovery | PRs 7, 8 | In Progress |
| [ENG-3594](https://linear.app/pomerium/issue/ENG-3594) | Wire upstream auth into controlplane | PR 6 | In Progress |
| [ENG-3596](https://linear.app/pomerium/issue/ENG-3596) | Extend /routes and /connect for auto-discovery | PR 8 | In Progress |
| [ENG-3597](https://linear.app/pomerium/issue/ENG-3597) | Demo: MCP proxying for autonomous agent | N/A (demo) | Ready |
