# PR Series: ext-proc-401-handle → main

## Status

| Category | Count | Details |
|----------|-------|---------|
| **Merged** | 10 | Foundation PRs (#6088, #6091, #6099, #6100, #6107, #6109, #6114) + #6118, #6119, #6121 |
| **Open (in review)** | 1 | #6130 (ext_proc handler interface) |
| **Remaining** | 5 | PRs 4a–6 below |

## Summary

The `ext-proc-401-handle` branch implements **upstream MCP OAuth handling via Envoy ext_proc**: when an upstream MCP server returns 401/403, Pomerium intercepts it, runs RFC 9728 PRM discovery, performs client registration (CIMD/DCR), and orchestrates the OAuth flow so the MCP client gets a token.

Remaining: **~4,400 lines of new/changed code** across 17 files (excluding docs/issues/generated protos).

---

## Merged Foundation PRs

| PR | Linear | Title | What it established |
|----|--------|-------|---------------------|
| [#6088](https://github.com/pomerium/pomerium/pull/6088) | [ENG-3525](https://linear.app/pomerium/issue/ENG-3525) | mcp: host Client ID Metadata Documents for auto-discovery mode | CIMD endpoint for MCP clients |
| [#6091](https://github.com/pomerium/pomerium/pull/6091) | [ENG-3528](https://linear.app/pomerium/issue/ENG-3528) | mcp: add ext_proc integration for response interception | ext_proc server scaffold, Envoy filter chain |
| [#6099](https://github.com/pomerium/pomerium/pull/6099) | [ENG-3555](https://linear.app/pomerium/issue/ENG-3555) | mcp: add upstream OAuth discovery core functions (RFC 9728/8414) | `runDiscovery()`, PRM + AS metadata fetching |
| [#6100](https://github.com/pomerium/pomerium/pull/6100) | [ENG-3556](https://linear.app/pomerium/issue/ENG-3556) | mcp: add upstream MCP token storage | Token CRUD, singleflight refresh |
| [#6107](https://github.com/pomerium/pomerium/pull/6107) | [ENG-3572](https://linear.app/pomerium/issue/ENG-3572) | mcp: add UpstreamOAuthClient type and storage for DCR caching | Client registration caching |
| [#6109](https://github.com/pomerium/pomerium/pull/6109) | [ENG-3570](https://linear.app/pomerium/issue/ENG-3570) | fix(mcp): CORS header consistency and e2e tests | CORS fixes, e2e test harness |
| [#6114](https://github.com/pomerium/pomerium/pull/6114) | — | databroker: add CompositeRecordID utility | Record ID builder for indexed lookups |
| [#6121](https://github.com/pomerium/pomerium/pull/6121) | [ENG-3600](https://linear.app/pomerium/issue/ENG-3600) | databroker: add first-class record auto-expiry via Options TTL | `Options.Ttl` for auto-expiring records |
| [#6118](https://github.com/pomerium/pomerium/pull/6118) | [ENG-3589](https://linear.app/pomerium/issue/ENG-3589) | mcp: add PendingUpstreamAuth proto and storage methods | `PendingUpstreamAuth` protobuf + CRUD |
| [#6119](https://github.com/pomerium/pomerium/pull/6119) | [ENG-3590](https://linear.app/pomerium/issue/ENG-3590) | mcp: pass upstream host via route context metadata and extend HostInfo | Route context metadata + `UpstreamURL` in HostInfo |

---

## Open PR (In Review)

### [#6130](https://github.com/pomerium/pomerium/pull/6130) — mcp: add ext_proc handler interface for upstream token injection — [ENG-3591](https://linear.app/pomerium/issue/ENG-3591)
**Base: `main`.** Defines the `UpstreamRequestHandler` interface and wires request/response handling into the ext_proc server.

**Files:**
- `internal/mcp/extproc/handler.go` (NEW, 83 lines — `UpstreamRequestHandler` interface + helpers)
- `internal/mcp/extproc/server.go` (+146/−31 — handler field, request/response logic)
- `internal/mcp/extproc/server_test.go` (+11/−10 — signature updates)
- `internal/controlplane/server.go` (+2 — pass `nil` handler)
- `internal/mcp/e2e/ext_proc_handler_test.go` (NEW — e2e tests with channel-based assertions)

**What it does:**
- Defines `UpstreamRequestHandler` interface: `GetUpstreamToken()` + `HandleUpstreamResponse()`
- Defines `UpstreamAuthAction` (WWW-Authenticate response)
- Helper functions: `injectAuthorizationHeader()`, `immediateUnauthorizedResponse()`
- ext_proc server captures downstream `:authority`, builds `originalURL` with upstream host
- On request: calls `handler.GetUpstreamToken()` → injects Authorization header
- On response 401/403: calls `handler.HandleUpstreamResponse()` → returns 401 to client
- All new behavior gated behind `handler == nil` checks

---

## Remaining PRs (5 PRs, ordered by dependency)

### PR 4a: Upstream OAuth setup utilities — [ENG-3592](https://linear.app/pomerium/issue/ENG-3592)
**Files (4 files, ~1,200 lines, all new):**
- `internal/mcp/upstream_token_exchange.go` (NEW, 48 lines — `exchangeToken()`)
- `internal/mcp/upstream_token_exchange_test.go` (NEW, 110 lines)
- `internal/mcp/upstream_oauth_setup.go` (NEW, ~450 lines — extracted pure functions)
- `internal/mcp/upstream_oauth_setup_test.go` (NEW, ~600 lines)

**What it does — pure functions, no handler dependency:**
- `exchangeToken()`: POST to token endpoint, parse JSON response (1MB body limit)
- `runUpstreamOAuthSetup()`: full discovery + client_id determination workflow
- `runDiscovery()` + `runDiscoveryFromPRM()` + `runDiscoveryFromFallbackAS()`: PRM/AS metadata fetching with fallback chain
- `registerWithUpstreamAS()`: RFC 7591 Dynamic Client Registration
- `getOrRegisterClient()`: CIMD preference, fallback to DCR with caching
- `selectScopes()`: WWW-Authenticate > PRM scopes
- `buildAuthorizationURL()`, `buildCallbackURL()`, `buildClientIDURL()`: URL construction
- `generatePKCE()`, `generateRandomString()`: PKCE challenge generation
- `stripPort()`, `stripQueryFromURL()`, `normalizeResourceURL()`, `originOf()`: URL helpers

**Depends on:** #6130 (ext_proc handler interface)
**Base branch:** `wasaga/mcp-ext-proc-handler-interface` (#6130) ← **ready to open now**

**Reviewability:** Easy. All pure/free functions with no side effects or state. Each function is independently testable. Key review points: discovery fallback chain, CIMD vs DCR strategy, URL construction correctness.

---

### PR 4b: UpstreamAuthHandler implementation — [ENG-3592](https://linear.app/pomerium/issue/ENG-3592)
**Files (4 files, ~1,500 lines):**
- `internal/mcp/upstream_auth.go` (NEW, ~500 lines — handler struct + methods)
- `internal/mcp/upstream_auth_test.go` (NEW, ~900 lines)
- `internal/mcp/host_info.go` (+10 — add `AuthorizationServerURL` field to `ServerHostInfo`)
- `authorize/route_context_metadata_test.go` (+24 — upstream_host test coverage)

**What it does — handler orchestration using PR 4a utilities:**
- `UpstreamAuthHandler` struct: implements `extproc.UpstreamRequestHandler`
- `NewUpstreamAuthHandler()`, `NewUpstreamAuthHandlerFromConfig()`: constructors
- `GetUpstreamToken()`: lookup cached token → route to static or auto-discovery path
  - `getStaticUpstreamOAuth2Token()`: singleflight token fetch for `upstream_oauth2` config routes
  - `getAutoDiscoveryToken()`: cached MCP token lookup + inline refresh if expired
- `HandleUpstreamResponse()`: dispatch 401/403 to `handle401()`
  - `handle401()`: calls `runUpstreamOAuthSetup()` (from PR 4a) → generates PKCE → stores pending auth → returns 401 action
- `refreshToken()`: token refresh with consistent RFC 8707 `resource` parameter
- `getUserID()`, `getUpstreamServerURL()`, `getServerInfo()`: helper methods
- `AuthorizationServerURL` field on `ServerHostInfo` for AS fallback when PRM discovery fails

**Depends on:** PR 4a (setup utilities)
**Base branch:** PR 4a branch

**Reviewability:** Medium. All new files (except minor `host_info.go` addition). Key review points: singleflight key security (includes userID), token refresh flow, pending auth state lifecycle, error handling.

---

### PR 5: OAuth callback + authorize changes + handler_connect refactoring + review findings tests — [ENG-3593](https://linear.app/pomerium/issue/ENG-3593), [ENG-3596](https://linear.app/pomerium/issue/ENG-3596)
**Files (10 files, +918/−164):**

*OAuth callback + authorize:*
- `internal/mcp/handler_client_oauth_callback.go` (NEW, 191 lines)
- `internal/mcp/handler.go` (+10/−8 — route wiring, httpClient option)
- `internal/mcp/handler_authorization.go` (+42 lines — auto-discovery flow in Authorize)
- `authorize/evaluator/headers_evaluator_evaluation.go` (+5/−13)
- `authorize/evaluator/headers_evaluator_test.go` (+28/−46)
- `authorize/internal/store/store.go` (+2/−6)

*Refactoring + new tests:*
- `internal/mcp/handler_connect.go` (+290/−73 — dual-path refactoring for upstream OAuth, fix port-stripping bug in `checkClientRedirectURL`)
- `internal/mcp/handler_list_routes.go` (+36/−18 — auto-discovery route filtering)
- `internal/mcp/handler_review_findings_test.go` (NEW, 667 lines — comprehensive test coverage)
- `internal/mcp/e2e/mcp_client_routes_test.go` (NEW, 336 lines — e2e tests for MCP client route management)

**What it does:**
- **ClientOAuthCallback**: Receives auth code + state → exchanges for tokens → stores upstream MCP token → cleans up pending state → completes MCP auth flow (or redirects)
- **Authorize changes**: For auto-discovery routes, proactively checks PRM → creates pending auth → redirects to upstream AS (single round-trip optimization)
- **Handler wiring**: Replaces `ClientOAuthCallbackStub` with real `ClientOAuthCallback`, adds `WithHTTPClient()` option
- **Header evaluator**: Removes `GetUpstreamOAuth2Token()` from authorize path — ext_proc now handles all upstream token injection
- **handler_connect refactoring**: Dual-path logic for auto-discovery vs static OAuth2 config routes; fix port-stripping bug in `checkClientRedirectURL`
- **handler_list_routes**: Filters routes based on auto-discovery capabilities
- **Review findings tests**: 667 lines of new test coverage for edge cases found during review
- **MCP client routes e2e tests**: 336 lines covering ListRoutes, ConnectGet, DisconnectRoutes

**Depends on:** PR 4b (UpstreamAuthHandler)
**Base branch:** Blocked — requires PR 4b to merge first

**Reviewability:** Medium-large. Changes span authorize + mcp packages. Key review points: callback security (state validation, PKCE), handler_connect dual-path logic, auto-discovery route filtering.

---

### PR 6: Controlplane wiring — [ENG-3594](https://linear.app/pomerium/issue/ENG-3594)
**Files (1 file, +15/−2):**
- `internal/controlplane/server.go` (+15/−2)

**What it does:**
- Adds `WithExtProcHandler()` option for test injection
- Auto-creates `UpstreamAuthHandler` via `mcp.NewUpstreamAuthHandlerFromConfig()` when MCP runtime flag is set
- Passes handler to `extproc.NewServer()`
- Graceful degradation: logs warning if handler creation fails, continues without token injection

**Depends on:** PR 5
**Base branch:** Blocked — requires PR 5 to merge first

**Reviewability:** Tiny. Quick review of wiring correctness.

---

## Dependency Graph

```
  (all merged into main)
  #6121 (TTL) ─→ #6118 (storage) ─┐
  #6119 (routing) ─────────────────┤
                                   ↓
                    #6130 (ext_proc interface) [OPEN]
                                   ↓
                    PR 4a (setup utilities, ~1,200 lines) ← NEXT TO OPEN (base: #6130)
                                   ↓
                    PR 4b (UpstreamAuthHandler, ~1,500 lines)
                                   ↓
                    PR 5 (callback + authorize + connect refactor + tests)
                                   ↓
                    PR 6 (controlplane wiring)
```

**Next PR to open:** PR 4a, based on `wasaga/mcp-ext-proc-handler-interface` (#6130). All prior dependencies (#6118, #6119, #6121) are merged into `main`, and #6130 already targets `main`. When #6130 merges, PR 4a will automatically rebase onto `main`.

## Linear Ticket ↔ PR Cross-Reference

| Linear Ticket | Title | PR | Status |
|---------------|-------|----|--------|
| [ENG-3525](https://linear.app/pomerium/issue/ENG-3525) | Host CIMD for auto-discovery mode | [#6088](https://github.com/pomerium/pomerium/pull/6088) | Merged |
| [ENG-3528](https://linear.app/pomerium/issue/ENG-3528) | ext_proc scaffolding for response interception | [#6091](https://github.com/pomerium/pomerium/pull/6091) | Merged |
| [ENG-3555](https://linear.app/pomerium/issue/ENG-3555) | Upstream OAuth discovery (RFC 9728/8414) | [#6099](https://github.com/pomerium/pomerium/pull/6099) | Merged |
| [ENG-3556](https://linear.app/pomerium/issue/ENG-3556) | Upstream MCP token storage | [#6100](https://github.com/pomerium/pomerium/pull/6100) | Merged |
| [ENG-3570](https://linear.app/pomerium/issue/ENG-3570) | Bug: mcp-inspector connect issue | [#6109](https://github.com/pomerium/pomerium/pull/6109) | Merged |
| [ENG-3572](https://linear.app/pomerium/issue/ENG-3572) | Cache DCR client registrations | [#6107](https://github.com/pomerium/pomerium/pull/6107) | Merged |
| [ENG-3600](https://linear.app/pomerium/issue/ENG-3600) | Databroker record auto-expiry via TTL | [#6121](https://github.com/pomerium/pomerium/pull/6121) | Merged |
| [ENG-3589](https://linear.app/pomerium/issue/ENG-3589) | PendingUpstreamAuth state storage | [#6118](https://github.com/pomerium/pomerium/pull/6118) | Merged |
| [ENG-3590](https://linear.app/pomerium/issue/ENG-3590) | Upstream host metadata + HostInfo | [#6119](https://github.com/pomerium/pomerium/pull/6119) | Merged |
| [ENG-3591](https://linear.app/pomerium/issue/ENG-3591) | ext_proc token injection + 401/403 interception | [#6130](https://github.com/pomerium/pomerium/pull/6130) | Open |
| [ENG-3592](https://linear.app/pomerium/issue/ENG-3592) | Upstream OAuth setup utilities | PR 4a | Ready to open |
| [ENG-3592](https://linear.app/pomerium/issue/ENG-3592) | UpstreamAuthHandler implementation | PR 4b | Blocked on PR 4a |
| [ENG-3593](https://linear.app/pomerium/issue/ENG-3593) | OAuth callback + authorize auto-discovery | PR 5 | Remaining |
| [ENG-3594](https://linear.app/pomerium/issue/ENG-3594) | Wire upstream auth into controlplane | PR 6 | Remaining |
| [ENG-3595](https://linear.app/pomerium/issue/ENG-3595) | Validate single upstream target per MCP route | Standalone | In QA |
| [ENG-3596](https://linear.app/pomerium/issue/ENG-3596) | Extend /routes and /connect for auto-discovery | PR 5 | Remaining |
| [ENG-3597](https://linear.app/pomerium/issue/ENG-3597) | Demo: MCP proxying for autonomous agent | N/A (demo) | Ready |

---

## Size Estimates

| PR | New Lines | Modified Lines | Files | Complexity |
|----|-----------|----------------|-------|------------|
| #6130 (open) | ~240 | ~40 | 5 | Medium |
| 4a (ready) | ~1,200 | 0 | 4 | Medium |
| 4b | ~1,400 | ~35 | 4 | Medium-High |
| 5 | ~920 | ~160 | 10 | Medium-High |
| 6 | ~15 | ~2 | 1 | Low |

## Build/Test Considerations

- Each PR should compile independently (`make build`)
- #6130, PR 4a, and PR 4b introduce no behavioral changes to existing code paths (all gated behind `handler == nil` checks)
- PR 4a is all new files with pure functions — zero risk to existing behavior
- PR 4b is all new files (except minor `host_info.go` addition) — no risk to existing behavior
- PR 5 is the "switch flip" that changes existing behavior (header evaluator stops injecting upstream tokens, authorize endpoint gains auto-discovery, handler_connect gets dual-path logic)
- PR 6 activates everything end-to-end
