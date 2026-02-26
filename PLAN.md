# PR Series: MCP Upstream OAuth + Service Accounts → main

## Status

| Category | Count | Details |
|----------|-------|---------|
| **Merged** | 15 | Foundation PRs (#6088, #6091, #6099, #6100, #6107, #6109, #6114, #6118, #6119, #6121) + #6130, #6133, #6137, #6144, #6145 |
| **Remaining** | 7 | PRs 4b, 4c, 6, 5a, 5b, 5c, 5d below |

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

## Remaining PRs (7 PRs, ordered by dependency)

### PR 4b: UpstreamAuthHandler core — [ENG-3592](https://linear.app/pomerium/issue/ENG-3592)
**Files (6 files, ~1,200 lines):**
- `internal/mcp/upstream_auth.go` (NEW, ~500 lines — handler struct + methods, session-only identity resolution)
- `internal/mcp/upstream_auth_test.go` (NEW, ~900 lines — tests for session paths, token refresh, 401 handling, singleflight)
- `internal/mcp/host_info.go` (+28 — add `AuthorizationServerURL` field to `ServerHostInfo`)
- `authorize/route_context_metadata_test.go` (+23 — upstream_host test coverage)
- Proto changes: `resource_param` field on `PendingUpstreamAuth` and `UpstreamMCPToken`
- Config changes: `AuthorizationServerURL` on `MCPServer` policy + conversion

**What it does:**
- `UpstreamAuthHandler` struct: implements `extproc.UpstreamRequestHandler`
- `NewUpstreamAuthHandler()`, `NewUpstreamAuthHandlerFromConfig()`: constructors with `*DomainMatcher` for SSRF-safe metadata validation
- `GetUpstreamToken()`: lookup cached token → route to static or auto-discovery path
  - `getStaticUpstreamOAuth2Token()`: singleflight token fetch for `upstream_oauth2` config routes
  - `getAutoDiscoveryToken()`: cached MCP token lookup + inline refresh if expired
- `HandleUpstreamResponse()`: dispatch 401/403 to `handle401()`
  - `handle401()`: calls `runUpstreamOAuthSetup()` → generates PKCE → stores pending auth → returns 401 action
- `refreshToken()`: token refresh with consistent RFC 8707 `resource` parameter
- `getSessionIdentity()`: resolves user ID from sessions (service account fallback added in PR 4c)
- `AuthorizationServerURL` field on `ServerHostInfo` for AS fallback when PRM discovery fails

**Depends on:** #6130, #6133, #6144, #6145 (all merged)
**Base branch:** `main` ← ready to open now

---

### PR 4c: Service account support for MCP routes — [ENG-3666](https://linear.app/pomerium/issue/ENG-3666)
**Files (3 files, ~400 lines):**
- `internal/mcp/upstream_auth.go` (+50 — `getSessionIdentity()` service account fallback, `handle401()` pass-through)
- `internal/mcp/upstream_auth_test.go` (+228 — service account test section: identity resolution, pass-through, token sharing, expiry, edge cases)
- `internal/mcp/storage.go` (+7 — `GetServiceAccount()` method on `HandlerStorage` interface + implementation)

**What it does:**
- `getSessionIdentity()` falls back from sessions to service accounts via `storage.GetServiceAccount()` when session lookup returns NotFound
- Validates service account expiry via `sa.Validate()`
- `handle401()` detects service accounts (`identity.IsServiceAccount`) and passes through upstream 401 unchanged — no interactive OAuth for non-interactive clients
- `GetUpstreamToken()` paths use `sessionIdentity.UserID` allowing service accounts to share upstream tokens provisioned by interactive users (same cache key: `user_id + route_id + upstream_server`)

**Depends on:** PR 4b
**Base branch:** Blocked — requires PR 4b to merge first

---

### PR 6: Controlplane wiring — [ENG-3594](https://linear.app/pomerium/issue/ENG-3594)
**Files (1 file, +15/−2):**
- `internal/controlplane/server.go` (+15/−2)

**What it does:**
- Adds `WithExtProcHandler()` option for test injection
- Auto-creates `UpstreamAuthHandler` via `mcp.NewUpstreamAuthHandlerFromConfig()` when MCP runtime flag is set
- Passes handler to `extproc.NewServer()`
- Graceful degradation: logs warning if handler creation fails, continues without token injection

**Why moved up:** PR 6 only needs the handler to exist (PR 4b). Moving it before PR 5x activates ext_proc token injection early, making the authorize evaluator cleanup in PR 5c safe (no gap where nobody injects tokens).

**Depends on:** PR 4c (handler + service accounts must exist)
**Base branch:** Blocked — requires PR 4c to merge first

---

### PR 5a: OAuth callback handler — [ENG-3593](https://linear.app/pomerium/issue/ENG-3593)
**Files (2 files, ~250 lines):**
- `internal/mcp/handler_client_oauth_callback.go` (NEW, 191 lines)
- `internal/mcp/handler.go` (+54/−54 — replace `ClientOAuthCallbackStub` with real handler, add `WithHTTPClient()`, wire `asMetadataDomainMatcher`)

**What it does:**
- `ClientOAuthCallback()`: receives auth code + state from upstream AS → validates pending auth state (expiry, PKCE) → exchanges code for tokens → stores `UpstreamMCPToken` → cleans up pending state → completes MCP auth flow via `AuthorizationResponse()` or redirects to original URL
- Handler wiring: replaces stub with real callback, adds `httpClient` and `asMetadataDomainMatcher` fields to Handler struct
- Conditional `client_secret` inclusion (public CIMD clients skip it)
- RFC 8707 `resource` parameter with fallback to `upstream_server` for backwards compatibility

**Depends on:** PR 6 (ext_proc must be active for the flow to work end-to-end)
**Base branch:** Blocked — requires PR 6 to merge first

---

### PR 5b: handler_connect dual-path + handler_list_routes — [ENG-3596](https://linear.app/pomerium/issue/ENG-3596)
**Files (2 files, ~350 lines):**
- `internal/mcp/handler_connect.go` (+290/−73 — dual-path refactoring, port-stripping bugfix)
- `internal/mcp/handler_list_routes.go` (+36/−18 — auto-discovery route filtering)

**What it does:**
- **handler_connect**: refactored from single-path to dual-path design:
  1. Static `upstream_oauth2` config path: existing flow (check token → AuthorizationRequest → redirect to login)
  2. Auto-discovery path: check cached MCP token → `resolveAutoDiscoveryAuth()` → redirect to upstream AS or back to client
  - Fix: `checkClientRedirectURL()` now uses `stripPort()` on redirect host (port validation bug)
- **handler_list_routes**: reports `NeedsOauth: true` for all MCP server routes; checks appropriate token store per route type (OAuth2 tokens for static, MCP tokens for auto-discovery); includes token expiry validation

**Depends on:** PR 5a (callback must be wired for connect flow to complete)
**Base branch:** Blocked — requires PR 5a to merge first

---

### PR 5c: Authorize auto-discovery + evaluator cleanup — [ENG-3593](https://linear.app/pomerium/issue/ENG-3593)
**Files (4 files, ~120 lines):**
- `internal/mcp/handler_authorization.go` (+42 — auto-discovery upstream OAuth in Authorize endpoint)
- `authorize/evaluator/headers_evaluator_evaluation.go` (+5/−13 — remove `GetUpstreamOAuth2Token()`, strip Authorization header for all MCP server routes)
- `authorize/evaluator/headers_evaluator_test.go` (+28/−46 — updated tests for header stripping)
- `authorize/internal/store/store.go` (+2/−6 — remove `GetUpstreamOAuth2Token()` from `MCPAccessTokenProvider` interface)

**What it does:**
- **Authorize auto-discovery**: for auto-discovery routes, proactively checks upstream PRM → creates pending auth → redirects to upstream AS in single round-trip (bypasses ext_proc 401 path when possible). Links `AuthReqID` to pending auth so callback can complete the MCP flow.
- **Evaluator cleanup**: removes upstream token injection from authorize path — ext_proc (activated in PR 6) is now the sole source of truth for upstream token injection. All MCP server routes consistently strip the Authorization header.

**Why safe:** By this point ext_proc is already active (PR 6) and injecting upstream tokens on the request path. Removing injection from authorize eliminates redundancy.

**Depends on:** PR 5b (auto-discovery connect flow must work first)
**Base branch:** Blocked — requires PR 5b to merge first

---

### PR 5d: Review findings tests + e2e coverage
**Files (2 files, ~1,000 lines):**
- `internal/mcp/handler_review_findings_test.go` (NEW, 677 lines)
- `internal/mcp/e2e/mcp_client_routes_test.go` (NEW, 336 lines)

**What it does:**
- **Review findings tests**: comprehensive test coverage for edge cases found during PR review — authorization flow variants, handler_connect dual-path logic, token refresh/expiry, error handling, session/service account handling, pending auth cleanup
- **MCP client routes e2e**: integration tests for `GET /.pomerium/mcp/routes`, `GET /.pomerium/mcp/connect`, `POST /.pomerium/mcp/routes/disconnect` — validates dual-path logic with real HTTP flows

**Depends on:** PR 5c (all behavior must be in place for tests to pass)
**Base branch:** Blocked — requires PR 5c to merge first

---

## Dependency Graph

```
  (all merged into main)
  #6130 (ext_proc interface) ──────┐
  #6133 (setup utilities) ─────────┤  ← MERGED
  #6144 (SSRF-safe client) ────────┤
  #6145 (DCR for upstream) ────────┤
                                   ↓
              PR 4b (UpstreamAuthHandler core, ~1,200 lines) ← NEXT TO OPEN
                                   ↓
              PR 4c (service account support, ~400 lines)
                                   ↓
              PR 6  (controlplane wiring, ~15 lines)
                                   ↓
              PR 5a (OAuth callback handler, ~250 lines)
                                   ↓
              PR 5b (handler_connect + list_routes, ~350 lines)
                                   ↓
              PR 5c (authorize auto-discovery + evaluator cleanup, ~120 lines)
                                   ↓
              PR 5d (review findings + e2e tests, ~1,000 lines)
```

**Next PR to open:** PR 4b, targeting `main`. All prior dependencies are merged.

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
| [ENG-3592](https://linear.app/pomerium/issue/ENG-3592) | Upstream OAuth setup + UpstreamAuthHandler | [#6133](https://github.com/pomerium/pomerium/pull/6133) + PR 4b | Partially merged |
| [ENG-3595](https://linear.app/pomerium/issue/ENG-3595) | Validate single upstream target per MCP route | Standalone | In QA |
| [ENG-3600](https://linear.app/pomerium/issue/ENG-3600) | Databroker record auto-expiry via TTL | [#6121](https://github.com/pomerium/pomerium/pull/6121) | Merged |
| [ENG-3650](https://linear.app/pomerium/issue/ENG-3650) | SSRF-safe AS metadata domain validation | [#6144](https://github.com/pomerium/pomerium/pull/6144) | Merged |
| [ENG-3654](https://linear.app/pomerium/issue/ENG-3654) | RFC 7591 DCR for upstream OAuth | [#6145](https://github.com/pomerium/pomerium/pull/6145) | Merged |
| [ENG-3666](https://linear.app/pomerium/issue/ENG-3666) | Service account support for MCP routes | PR 4c | In Progress |
| [ENG-3593](https://linear.app/pomerium/issue/ENG-3593) | OAuth callback + authorize auto-discovery | PR 5a, 5c | In Progress |
| [ENG-3594](https://linear.app/pomerium/issue/ENG-3594) | Wire upstream auth into controlplane | PR 6 | In Progress |
| [ENG-3596](https://linear.app/pomerium/issue/ENG-3596) | Extend /routes and /connect for auto-discovery | PR 5b | In Progress |
| [ENG-3597](https://linear.app/pomerium/issue/ENG-3597) | Demo: MCP proxying for autonomous agent | N/A (demo) | Ready |

---

## Size Estimates

| PR | Lines | Files | Complexity | Review focus |
|----|-------|-------|------------|--------------|
| 4b | ~1,200 | 6 | Medium | Singleflight keying, token refresh, SSRF domain matcher wiring |
| 4c | ~400 | 3 | Low-Medium | Session→SA fallback, 401 pass-through, token sharing via user ID |
| 6 | ~15 | 1 | Low | Wiring correctness, graceful degradation |
| 5a | ~250 | 2 | Medium | Callback security (state/PKCE validation), pending auth lifecycle |
| 5b | ~350 | 2 | Medium | Dual-path logic, port-stripping bugfix, token store per route type |
| 5c | ~120 | 4 | Low-Medium | Authorize package changes, token injection handoff to ext_proc |
| 5d | ~1,000 | 2 | Low | Pure tests, no behavior change |

## Build/Test Considerations

- Each PR should compile independently (`make build`)
- PR 4b introduces `UpstreamAuthHandler` with session-only identity; all new behavior gated behind `handler == nil` checks
- PR 4c adds service account fallback — additive, doesn't change existing session behavior
- PR 6 activates ext_proc token injection; after this merges, both authorize and ext_proc inject tokens (redundant but safe — ext_proc overwrites)
- PR 5a wires the OAuth callback — completes the upstream OAuth code exchange flow
- PR 5b enables client-facing endpoints to handle auto-discovery routes
- PR 5c removes redundant token injection from authorize (safe because ext_proc is already active from PR 6)
- PR 5d adds test coverage for all the above — can serve as final validation
