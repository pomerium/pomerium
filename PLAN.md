# PR Series: ext-proc-401-handle → main

## Status

| Category | Count | Details |
|----------|-------|---------|
| **Merged** | 7 | Foundation PRs (#6088, #6091, #6099, #6100, #6107, #6109, #6114) |
| **Open (in review)** | 3 | #6118 (storage), #6119 (routing), #6121 (TTL) |
| **Remaining** | 4 | PRs 3–6 below |

## Summary

The `ext-proc-401-handle` branch implements **upstream MCP OAuth handling via Envoy ext_proc**: when an upstream MCP server returns 401/403, Pomerium intercepts it, runs RFC 9728 PRM discovery, performs client registration (CIMD/DCR), and orchestrates the OAuth flow so the MCP client gets a token.

Remaining: **~3,700 lines of new/changed code** across 18 files (excluding docs/issues/generated protos).

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

---

## Open PRs (In Review)

### [#6121](https://github.com/pomerium/pomerium/pull/6121) — databroker: add first-class record auto-expiry via Options TTL — [ENG-3600](https://linear.app/pomerium/issue/ENG-3600)
**Prerequisite for #6118.** Adds `Options.Ttl` to databroker proto so records can auto-expire.

**Files:**
- `pkg/grpc/databroker/databroker.proto` (+6 lines)
- `pkg/grpc/databroker/databroker.pb.go` (generated)
- `internal/databroker/server_backend.go` (+43 lines)
- `pkg/storage/storage.go` (+3 lines)
- `pkg/storage/file/backend.go` (+49 lines)
- `pkg/storage/postgres/backend.go` (+27 lines)
- `pkg/storage/postgres/migrate.go` (+17 lines)
- `pkg/storage/postgres/postgres.go` (+46 lines)
- `pkg/storage/storagetest/storagetest.go` (+219 lines)

### [#6118](https://github.com/pomerium/pomerium/pull/6118) — mcp: add PendingUpstreamAuth proto and storage methods — [ENG-3589](https://linear.app/pomerium/issue/ENG-3589)
**Blocked by #6121.** Defines `PendingUpstreamAuth` protobuf and CRUD storage methods with databroker indexing.

**Files:**
- `internal/oauth21/proto/pending_upstream_auth.proto` (NEW, 84 lines)
- `internal/oauth21/gen/pending_upstream_auth.pb.go` (generated)
- `internal/mcp/storage.go` (+100 lines)

### [#6119](https://github.com/pomerium/pomerium/pull/6119) — mcp: pass upstream host via route context metadata and extend HostInfo — [ENG-3590](https://linear.app/pomerium/issue/ENG-3590)
Route context metadata plumbing + HostInfo upstream URL tracking.

**Files:**
- `authorize/route_context_metadata.go` (+8 lines)
- `authorize/route_context_metadata_test.go` (+23 lines)
- `internal/mcp/host_info.go` (+22 lines)
- `internal/mcp/host_info_test.go` (+91 lines)

---

## Remaining PRs (4 PRs, ordered by dependency)

### PR 3: ext_proc handler interface + server request/response handling — [ENG-3591](https://linear.app/pomerium/issue/ENG-3591)
**Files (3 files, +240/−41):**
- `internal/mcp/extproc/handler.go` (NEW, 83 lines — `UpstreamRequestHandler` interface + helpers)
- `internal/mcp/extproc/server.go` (+146/−31 — handler field, request/response logic)
- `internal/mcp/extproc/server_test.go` (+11/−10 — signature updates)

**What it does:**
- Defines `UpstreamRequestHandler` interface: `GetUpstreamToken()` + `HandleUpstreamResponse()`
- Defines `UpstreamAuthAction` (WWW-Authenticate response)
- Helper functions: `injectAuthorizationHeader()`, `immediateUnauthorizedResponse()`
- ext_proc server now:
  - Captures downstream `:authority` and builds `originalURL` with upstream host
  - On request: calls `handler.GetUpstreamToken()` → injects Authorization header
  - On response 401/403: calls `handler.HandleUpstreamResponse()` → returns 401 to client
  - Adds `UpstreamHost` to `RouteContext`

**Depends on:** #6119 (routing metadata)

**Reviewability:** Medium. Core ext_proc orchestration logic. Key review points: URL construction (downstream vs upstream), pseudo-header RawValue handling, error passthrough behavior.

---

### PR 4: Token exchange + upstream auth core implementation — [ENG-3592](https://linear.app/pomerium/issue/ENG-3592)
**Files (4 files, +1,995/−0, all new):**
- `internal/mcp/upstream_token_exchange.go` (NEW, 48 lines)
- `internal/mcp/upstream_token_exchange_test.go` (NEW, 110 lines)
- `internal/mcp/upstream_auth.go` (NEW, 768 lines)
- `internal/mcp/upstream_auth_test.go` (NEW, 1,069 lines)

**What it does:**
- `exchangeToken()`: POST to token endpoint, parse JSON response (1MB body limit)
- `UpstreamAuthHandler` implements `UpstreamRequestHandler`:
  - `GetUpstreamToken()`: lookup cached token → inline refresh if expired → return bearer token
  - `HandleUpstreamResponse()`: PRM discovery → AS metadata → client registration (CIMD/DCR) → PKCE/state → store pending auth → return WWW-Authenticate
  - `getOrRegisterClient()`: CIMD preference, fallback to DCR with caching
  - `selectScopes()`: WWW-Authenticate > PRM scopes
  - `buildAuthorizationURL()`, `buildCallbackURL()`, `buildClientIDURL()`
  - Singleflight for concurrent token refresh dedup
- Comprehensive test suite (21 test functions)

**Scope note:** Discovery functions (`runDiscovery`, PRM/AS metadata) and token/client storage were extracted into the merged foundation PRs (#6099, #6100, #6107). This PR now contains only the orchestration logic and token exchange.

**Depends on:** #6118 (storage), PR 3 (interface contract)

**Reviewability:** Large but self-contained. All new files, no modifications to existing code. Key review points: discovery validation, CIMD vs DCR strategy, singleflight key security (includes userID), error handling.

---

### PR 5: OAuth callback + authorize changes + handler_connect refactoring + review findings tests — [ENG-3593](https://linear.app/pomerium/issue/ENG-3593), [ENG-3596](https://linear.app/pomerium/issue/ENG-3596)
**Files (10 files, +918/−164):**

*OAuth callback + authorize (unchanged from original plan):*
- `internal/mcp/handler_client_oauth_callback.go` (NEW, 168 lines)
- `internal/mcp/handler.go` (+10/−8 — route wiring, httpClient option)
- `internal/mcp/handler_authorization.go` (+42 lines — auto-discovery flow in Authorize)
- `authorize/evaluator/headers_evaluator_evaluation.go` (+5/−13)
- `authorize/evaluator/headers_evaluator_test.go` (+28/−46)
- `authorize/internal/store/store.go` (+2/−6)

*Expanded scope — refactoring + new tests:*
- `internal/mcp/handler_connect.go` (+290/−73 — dual-path refactoring for upstream OAuth, fix port-stripping bug in `checkClientRedirectURL`)
- `internal/mcp/handler_list_routes.go` (+36/−18 — auto-discovery route filtering)
- `internal/mcp/handler_review_findings_test.go` (NEW, 667 lines — comprehensive test coverage)
- `internal/mcp/e2e/mcp_client_routes_test.go` (NEW, 337 lines — e2e tests for MCP client route management)

**What it does:**
- **ClientOAuthCallback**: Receives auth code + state → exchanges for tokens → stores upstream MCP token → cleans up pending state → completes MCP auth flow (or redirects)
- **Authorize changes**: For auto-discovery routes, proactively checks PRM → creates pending auth → redirects to upstream AS (single round-trip optimization)
- **Handler wiring**: Replaces `ClientOAuthCallbackStub` with real `ClientOAuthCallback`, adds `WithHTTPClient()` option
- **Header evaluator**: Removes `GetUpstreamOAuth2Token()` from authorize path — ext_proc now handles all upstream token injection
- **handler_connect refactoring**: Dual-path logic for auto-discovery vs static OAuth2 config routes; fix port-stripping bug in `checkClientRedirectURL` where `redirectURLParsed.Host` (includes port) was passed to `IsMCPClientForHost` (keyed by hostname without port)
- **handler_list_routes**: Filters routes based on auto-discovery capabilities
- **Review findings tests**: 667 lines of new test coverage for edge cases found during review
- **MCP client routes e2e tests**: 337 lines covering ListRoutes (server list, no-cache headers), ConnectGet (redirect_url validation, auto-discovery fallthrough), and DisconnectRoutes (input validation, bulk disconnect)

**Depends on:** PR 4 (upstream_auth functions)

**Reviewability:** Medium-large. Changes span authorize + mcp packages. Key review points: callback security (state validation, PKCE), handler_connect dual-path logic, auto-discovery route filtering.

---

### PR 6: Controlplane wiring + e2e test update — [ENG-3594](https://linear.app/pomerium/issue/ENG-3594)
**Files (2 files, +23/−2):**
- `internal/controlplane/server.go` (+22/−2)
- `internal/mcp/e2e/ext_proc_test.go` (+1 line)

**What it does:**
- Adds `WithExtProcHandler()` option for test injection
- Auto-creates `UpstreamAuthHandler` via `mcp.NewUpstreamAuthHandlerFromConfig()` when MCP runtime flag is set
- Passes handler to `extproc.NewServer()`
- Graceful degradation: logs warning if handler creation fails, continues without token injection

**Depends on:** PR 5

**Reviewability:** Tiny. Quick review of wiring correctness.

---

## Dependency Graph

```
#6121 (databroker TTL)           #6119 (routing metadata)
  ↓                                ↓
#6118 (proto + storage)            │
  ↓                                │
  └──────────┬─────────────────────┘
             ↓
  PR 3 (ext_proc interface + server)
             ↓
  PR 4 (token exchange + upstream auth core)
             ↓
  PR 5 (callback + authorize + connect refactor + tests)
             ↓
  PR 6 (controlplane wiring)
```

## Linear Ticket ↔ PR Cross-Reference

| Linear Ticket | Title | PR | Status |
|---------------|-------|----|--------|
| [ENG-3525](https://linear.app/pomerium/issue/ENG-3525) | Host CIMD for auto-discovery mode | [#6088](https://github.com/pomerium/pomerium/pull/6088) | Merged |
| [ENG-3528](https://linear.app/pomerium/issue/ENG-3528) | ext_proc scaffolding for response interception | [#6091](https://github.com/pomerium/pomerium/pull/6091) | Merged |
| [ENG-3555](https://linear.app/pomerium/issue/ENG-3555) | Upstream OAuth discovery (RFC 9728/8414) | [#6099](https://github.com/pomerium/pomerium/pull/6099) | Merged |
| [ENG-3556](https://linear.app/pomerium/issue/ENG-3556) | Upstream MCP token storage | [#6100](https://github.com/pomerium/pomerium/pull/6100) | Merged |
| [ENG-3570](https://linear.app/pomerium/issue/ENG-3570) | Bug: mcp-inspector connect issue | [#6109](https://github.com/pomerium/pomerium/pull/6109) | Merged |
| [ENG-3572](https://linear.app/pomerium/issue/ENG-3572) | Cache DCR client registrations | [#6107](https://github.com/pomerium/pomerium/pull/6107) | Merged |
| [ENG-3600](https://linear.app/pomerium/issue/ENG-3600) | Databroker record auto-expiry via TTL | [#6121](https://github.com/pomerium/pomerium/pull/6121) | Open |
| [ENG-3589](https://linear.app/pomerium/issue/ENG-3589) | PendingUpstreamAuth state storage | [#6118](https://github.com/pomerium/pomerium/pull/6118) | Open |
| [ENG-3590](https://linear.app/pomerium/issue/ENG-3590) | Upstream host metadata + HostInfo | [#6119](https://github.com/pomerium/pomerium/pull/6119) | Open |
| [ENG-3591](https://linear.app/pomerium/issue/ENG-3591) | ext_proc token injection + 401/403 interception | PR 3 | Remaining |
| [ENG-3592](https://linear.app/pomerium/issue/ENG-3592) | Upstream OAuth discovery/registration/tokens | PR 4 | Remaining |
| [ENG-3593](https://linear.app/pomerium/issue/ENG-3593) | OAuth callback + authorize auto-discovery | PR 5 | Remaining |
| [ENG-3594](https://linear.app/pomerium/issue/ENG-3594) | Wire upstream auth into controlplane | PR 6 | Remaining |
| [ENG-3595](https://linear.app/pomerium/issue/ENG-3595) | Validate single upstream target per MCP route | Standalone | In QA |
| [ENG-3596](https://linear.app/pomerium/issue/ENG-3596) | Extend /routes and /connect for auto-discovery | PR 5 | Remaining |
| [ENG-3597](https://linear.app/pomerium/issue/ENG-3597) | Demo: MCP proxying for autonomous agent | N/A (demo) | Ready |

---

## Size Estimates

| PR | New Lines | Modified Lines | Files | Complexity |
|----|-----------|----------------|-------|------------|
| #6121 (open) | ~360 | ~50 | 9 | Low |
| #6118 (open) | ~190 | 0 | 3 | Low |
| #6119 (open) | ~145 | 0 | 4 | Low |
| 3 | ~240 | ~40 | 3 | Medium |
| 4 | ~1,995 | 0 | 4 | High |
| 5 | ~920 | ~160 | 10 | Medium-High |
| 6 | ~23 | ~2 | 2 | Low |

## Build/Test Considerations

- Each PR should compile independently (`make build`)
- PRs 3–4 introduce no behavioral changes to existing code paths (all gated behind `handler == nil` checks)
- PR 4 is all new files — no risk to existing behavior
- PR 5 is the "switch flip" that changes existing behavior (header evaluator stops injecting upstream tokens, authorize endpoint gains auto-discovery, handler_connect gets dual-path logic)
- PR 6 activates everything end-to-end
