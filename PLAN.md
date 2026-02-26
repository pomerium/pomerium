# PR Series: ext-proc-401-handle → main

## Status

| Category | Count | Details |
|----------|-------|---------|
| **Merged** | 15 | Foundation PRs (#6088, #6091, #6099, #6100, #6107, #6109, #6114, #6118, #6119, #6121) + #6130, #6133, #6137, #6144, #6145 |
| **Remaining** | 3 | PRs 4b, 5, 6 below |

## Summary

The `ext-proc-401-handle` branch (now continued as `mcp-service-accounts`) implements **upstream MCP OAuth handling via Envoy ext_proc**: when an upstream MCP server returns 401/403, Pomerium intercepts it, runs RFC 9728 PRM discovery, performs client registration (CIMD), and orchestrates the OAuth flow so the MCP client gets a token.

**New on this branch:** MCP service account support for non-interactive clients (e.g., autonomous agents). Service accounts can reuse upstream tokens provisioned by interactive user flows, and are correctly identified via `getSessionIdentity()` fallback from sessions to service accounts. When service accounts encounter upstream 401s, they pass through rather than attempting interactive OAuth flows.

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
| [#6144](https://github.com/pomerium/pomerium/pull/6144) | — | feat: add SSRF-safe HTTP client for MCP metadata fetching | SSRF protection, `DomainMatcher`, `MCPAllowedASMetadataDomains` config |
| [#6145](https://github.com/pomerium/pomerium/pull/6145) | — | feat: add DCR for upstream OAuth | `UpstreamOAuthClient` storage, `HandlerStorage` export, DCR caching |

---

## Remaining PRs (3 PRs, ordered by dependency)

### PR 4b: UpstreamAuthHandler implementation — [ENG-3592](https://linear.app/pomerium/issue/ENG-3592)
**Files (4 files, ~1,500 lines):**
- `internal/mcp/upstream_auth.go` (NEW, ~500 lines — handler struct + methods)
- `internal/mcp/upstream_auth_test.go` (NEW, ~900 lines)
- `internal/mcp/host_info.go` (+10 — add `AuthorizationServerURL` field to `ServerHostInfo`)
- `authorize/route_context_metadata_test.go` (+24 — upstream_host test coverage)

**What it does — handler orchestration using merged setup utilities:**
- `UpstreamAuthHandler` struct: implements `extproc.UpstreamRequestHandler`
- `NewUpstreamAuthHandler()`, `NewUpstreamAuthHandlerFromConfig()`: constructors (now with `*DomainMatcher` for SSRF-safe metadata validation)
- `GetUpstreamToken()`: lookup cached token → route to static or auto-discovery path
  - `getStaticUpstreamOAuth2Token()`: singleflight token fetch for `upstream_oauth2` config routes
  - `getAutoDiscoveryToken()`: cached MCP token lookup + inline refresh if expired
- `HandleUpstreamResponse()`: dispatch 401/403 to `handle401()`
  - `handle401()`: calls `runUpstreamOAuthSetup()` → generates PKCE → stores pending auth → returns 401 action
  - Service accounts pass through upstream 401 (no interactive OAuth)
- `refreshToken()`: token refresh with consistent RFC 8707 `resource` parameter
- `getSessionIdentity()`: resolves user ID from sessions or service accounts
- `AuthorizationServerURL` field on `ServerHostInfo` for AS fallback when PRM discovery fails

**Depends on:** #6130, #6133, #6144, #6145 (all merged)
**Base branch:** `main` ← **ready to open now**

**Reviewability:** Medium. All new files (except minor `host_info.go` addition). Key review points: singleflight key security (includes userID), service account handling, token refresh flow, pending auth state lifecycle, SSRF domain matcher wiring.

---

### PR 5: OAuth callback + authorize changes + handler_connect refactoring + review findings tests — [ENG-3593](https://linear.app/pomerium/issue/ENG-3593), [ENG-3596](https://linear.app/pomerium/issue/ENG-3596)
**Files (10 files, +918/−164):**

*OAuth callback + authorize:*
- `internal/mcp/handler_client_oauth_callback.go` (NEW, 191 lines)
- `internal/mcp/handler.go` (+10/−8 — route wiring, httpClient option, asMetadataDomainMatcher)
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
- **Handler wiring**: Replaces `ClientOAuthCallbackStub` with real `ClientOAuthCallback`, adds `WithHTTPClient()` option, wires `asMetadataDomainMatcher`
- **Header evaluator**: Removes `GetUpstreamOAuth2Token()` from authorize path — ext_proc now handles all upstream token injection
- **handler_connect refactoring**: Dual-path logic for auto-discovery vs static OAuth2 config routes; fix port-stripping bug in `checkClientRedirectURL`; passes `WithASMetadataDomainMatcher` to `runUpstreamOAuthSetup` for SSRF safety
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
  #6130 (ext_proc interface) ──────┤  ← MERGED
  #6133 (setup utilities) ─────────┤  ← MERGED
  #6144 (SSRF-safe client) ────────┤  ← MERGED
  #6145 (DCR for upstream) ────────┤  ← MERGED
                                   ↓
                    PR 4b (UpstreamAuthHandler, ~1,500 lines) ← NEXT TO OPEN (base: main)
                                   ↓
                    PR 5 (callback + authorize + connect refactor + tests)
                                   ↓
                    PR 6 (controlplane wiring)
```

**Next PR to open:** PR 4b, targeting `main`. All prior dependencies are merged. This PR introduces the `UpstreamAuthHandler` struct that implements the `extproc.UpstreamRequestHandler` interface, plus service account support.

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
| [ENG-3591](https://linear.app/pomerium/issue/ENG-3591) | ext_proc token injection + 401/403 interception | [#6130](https://github.com/pomerium/pomerium/pull/6130) | Merged |
| [ENG-3592](https://linear.app/pomerium/issue/ENG-3592) | Upstream OAuth setup utilities | [#6133](https://github.com/pomerium/pomerium/pull/6133) | Merged |
| [ENG-3592](https://linear.app/pomerium/issue/ENG-3592) | UpstreamAuthHandler implementation | PR 4b | Ready to open |
| [ENG-3593](https://linear.app/pomerium/issue/ENG-3593) | OAuth callback + authorize auto-discovery | PR 5 | Remaining |
| [ENG-3594](https://linear.app/pomerium/issue/ENG-3594) | Wire upstream auth into controlplane | PR 6 | Remaining |
| [ENG-3595](https://linear.app/pomerium/issue/ENG-3595) | Validate single upstream target per MCP route | Standalone | In QA |
| [ENG-3596](https://linear.app/pomerium/issue/ENG-3596) | Extend /routes and /connect for auto-discovery | PR 5 | Remaining |
| [ENG-3597](https://linear.app/pomerium/issue/ENG-3597) | Demo: MCP proxying for autonomous agent | N/A (demo) | Ready |

---

## Size Estimates

| PR | New Lines | Modified Lines | Files | Complexity |
|----|-----------|----------------|-------|------------|
| 4b (ready) | ~1,400 | ~35 | 4 | Medium-High |
| 5 | ~920 | ~160 | 10 | Medium-High |
| 6 | ~15 | ~2 | 1 | Low |

## Build/Test Considerations

- Each PR should compile independently (`make build`)
- PR 4b introduces `UpstreamAuthHandler` with SSRF-safe domain matcher wiring (required by #6144); all new behavior gated behind `handler == nil` checks
- PR 5 is the "switch flip" that changes existing behavior (header evaluator stops injecting upstream tokens, authorize endpoint gains auto-discovery, handler_connect gets dual-path logic)
- PR 6 activates everything end-to-end

## Branch-Specific Notes (mcp-service-accounts)

This branch extends the upstream auth flow with service account support:
- `getSessionIdentity()` in `upstream_auth.go` falls back from sessions to service accounts via `storage.GetServiceAccount()`
- `handle401()` detects service accounts and passes through 401 (no interactive OAuth)
- `GetUpstreamToken()` paths use `sessionIdentity.UserID` allowing service accounts to share upstream tokens provisioned by interactive users
- All service account code paths have dedicated test coverage in `upstream_auth_test.go`
