# Pomerium observability e2e suite (logging / metrics / tracing)

Container-based end-to-end tests for Pomerium's observability surface, automating the QA test
plans **Core.Logging**, **Core.Metrics**, and **Core.OTEL Tracing** (Notion → QA → Test Plans →
Core). Everything runs in containers via [testcontainers](https://node.testcontainers.org/)
against the **official `pomerium/pomerium` image**, with a real Keycloak IdP (shared realm
fixture), the `pomerium/verify` upstream, and a real Jaeger collector for OTLP spans.

Upstream TLS/mTLS is covered by its own harness (`../upstream-tls`, PR #6648) and is
deliberately out of scope here.

## Topology

```
browser / API (host)
   │
   ▼
pomerium :8443  (official image; config generated per test into .gen/ and bind-mounted)
   │   └── route https://verify.localhost.pomerium.io:8443 → http://upstream:8000  (pomerium/verify)
   ├── OIDC → keycloak.localhost.pomerium.io:8080  (realm import from ../../keycloak)
   ├── OTLP → jaeger:4317 / 4318   (in-network; tests query http://127.0.0.1:16686)
   └── metrics listener :9902      (when metrics_address is configured)
```

Every service sits on one Docker network with a `*.localhost.pomerium.io` alias that also
resolves to `127.0.0.1` publicly, and fixed identical host/container ports — the same URL means
the same thing to the browser and to the containers. The config-invariant services (Keycloak,
verify, Jaeger) boot once in Playwright's global setup; **Pomerium restarts per test** with that
case's generated configuration.

### Fixed host ports

| Port  | Service |
|-------|---------|
| 8443  | Pomerium (HTTPS + authenticate) |
| 8080  | Keycloak |
| 9902  | Pomerium metrics listener (published always; listening only when configured) |
| 16686 | Jaeger query API / UI |

Because of the fixed ports the suite runs with `workers: 1` and **cannot run concurrently** with
`make up`, the other container suites, or anything else holding those ports.

> **Network exposure while tests run** — Docker publishes these ports on **all interfaces**
> (testcontainers sets no host IP), so for the duration of a run they are reachable from your
> local network: the Jaeger UI has no authentication by design, and Keycloak boots with test
> `admin/admin` credentials. Everything in the stack is synthetic (throwaway users, secrets and
> spans), but prefer a trusted network or CI for running the suite.

## Prerequisites

- Docker
- Node.js ≥ 22 (see `.tool-versions`)
- [mkcert](https://github.com/FiloSottile/mkcert) on the PATH (`brew install mkcert`).
  No `mkcert -install` needed — the browser ignores TLS errors; mkcert just mints the wildcard
  leaf Pomerium serves.

## Running

```bash
# from internal/acceptance
make deps-observability     # npm ci (workspace) + Playwright Chromium + pull pomerium:main
make test-observability     # the whole suite
make test-observability-headed

# from this directory
npx playwright test                       # everything
npx playwright test tests/metrics.spec.ts # one file
OBS_E2E_LOGS=1 npx playwright test        # stream container logs
```

Useful while debugging: the Jaeger UI at <http://127.0.0.1:16686> shows every span the run
exported (the store persists for the whole run).

Image overrides: `POMERIUM_IMAGE` (default `pomerium/pomerium:main`, always re-pulled for
mutable tags), `VERIFY_IMAGE`, `JAEGER_IMAGE` (default pinned `jaegertracing/jaeger:2.20.0`).

## How the tests work

- **Per-test Pomerium configs** — `setup/pomerium-config.ts` writes each case's config as JSON
  (valid YAML) into `.gen/<name>.yaml`; `startPomerium` bind-mounts it read-only at
  `/pomerium/config.yaml`. Tests start Pomerium **inside the test body** (`withPomerium`), so a
  CI retry rebuilds the container instead of reusing a torn-down one.
- **Log assertions** — everything Pomerium emits is JSON on stdout, captured line-by-line.
  Access logs (`"message":"http-request"`) flush from Envoy on a ~1s interval, so tests
  `quiesceLogs()` (drain + clear) *before* the traffic under test and poll with
  `waitForEntry()` after. Field configuration is asserted as **exact key sets**:
  `assertLogFields(entry, kind, expected)` requires the expected fields plus the always-on
  envelope and rejects *every* other key, so a test names only what it configured. Checking the
  complement of the allowed set — rather than a hand-maintained mirror of `AllAccessLogFields()` /
  `AllAuthorizeLogFields()` — means a field added to `pkg/logfields` cannot silently stop being
  checked. TC-LOG-04 pins the envelope list itself by configuring zero fields.
- **Metrics assertions** — plain `fetch` against `http://127.0.0.1:9902`. `/metrics` is
  Pomerium's aggregated handler (`pomerium_*` + scraped `envoy_*`, the only path
  `metrics_basic_auth` covers); `/metrics/envoy` is Envoy's raw `/stats/prometheus` and is
  deliberately asserted to be reachable **without** credentials (documented gap).
  Config-rejection cases use `startPomeriumExpectExit` and assert the exact load-time error.
- **Tracing assertions** — Pomerium exports OTLP to Jaeger in-network; tests read spans back via
  the classic query API. Every test scopes its queries with a unique **marker path**
  (`/e2e/<case>-<uuid8>`) because Jaeger's store persists across tests. "No spans" negatives
  wait out a fixed window and then query once — Jaeger keeps every span and the query looks back
  an hour, so one query after the window is as conclusive as polling through it. The window must
  outlast the batch delay of the config under test: 6s by default (Pomerium's SDK batches on 5s),
  3s for Envoy-only assertions (the tracing configs set `otel_bsp_schedule_delay: 1000` — an
  integer in **milliseconds**, not a duration string). Positive cases run before negatives in the
  same file so a broken export pipeline fails loudly instead of green-lighting a negative.
- **Jaeger UI journeys** — `tracing-journeys.spec.ts` asserts through the **browser** instead of the
  query API: the same Chromium that signed in opens <http://127.0.0.1:16686>, searches, clicks into a
  trace and reads it. Each step is a `test.step` and the Jaeger interaction is written out in the test
  body (no helper), so the HTML report, the video and the retained trace all read as the journey.
  Two waits are inherent and appear as `expect(async () => { await page.reload(); … }).toPass()`
  loops: the Service dropdown is filled on page load, so it is reloaded until Envoy is known; and
  Pomerium's own spans join a trace ~4s after Envoy's, so the search row is reloaded until it lists
  `Control Plane` **before** the trace is opened — Jaeger's UI caches a fetched trace, so opening it
  early would pin a partial one. Locators are testid/role-first with three class-based exceptions
  (`.ant-select-item-option`, `a.span-name`, `.TracePageSearchBar`); `JAEGER_IMAGE` is
  digest-pinned, so **bumping Jaeger means re-capturing these selectors**.
- **Traffic** — the **logging** cases use an `allow_any_authenticated_user: true` route (the QA
  plans' base config) and open it **in a real browser** after a real Keycloak sign-in, so the field
  configuration is asserted against the traffic a user actually produces — the sign-in redirects
  through the authenticate host and the page's sub-resource requests included. Because several
  entries land per navigation, and because a reduced field list may leave nothing to identify an
  individual request, those cases assert the field set across *every* captured entry
  (`assertAllLogFields`) rather than picking one line. The **metrics** and **tracing** cases use an
  `allow_public_unauthenticated_access` route with a request context instead: they only need traffic
  through the route, and skipping sign-in keeps their logs and spans clean.

## Test case map

| Spec | Cases |
|------|-------|
| `logging-access.spec.ts` | TC-LOG-01 default access fields (exact 12) · TC-LOG-02 single field suppresses the rest · TC-LOG-03 `headers.<Name>` nested object · TC-LOG-04 empty list logs the envelope only (pins the envelope) |
| `logging-authorize.spec.ts` | TC-LOG-10 default authorize fields for a signed-in request (13 materialized of 18 configured; decision fields always appended) · TC-LOG-11 `headers.Cookie` · TC-LOG-12 single field · TC-LOG-13 the sign-in decision trail: unauthenticated denial → internal `pomerium-route` checks → `user-ok` allow, plus the authenticate service's own log lines |
| `metrics.spec.ts` | TC-MET-01 no `metrics_address` → port closed · TC-MET-02/03 aggregated `/metrics` (build info + envoy counters after traffic) and raw `/metrics/envoy`, sharing one container · TC-MET-04 basic auth (401/401/200) and the unprotected envoy path · TC-MET-05 malformed basic auth rejected at load (ENG-4311 fix guard) |
| `tracing-enablement.spec.ts` | TC-TRC-01 exporter+generic endpoint → Envoy & Pomerium spans (ENG-1960 guard) · TC-TRC-04 traces-specific endpoint · TC-TRC-02 exporter only → none · TC-TRC-03 endpoint only → none · TC-TRC-05 exporter `none` · TC-TRC-06 `OTEL_SDK_DISABLED=true` |
| `tracing-spans.spec.ts` | TC-TRC-10 one request → one trace, Envoy (`pomerium.envoy=true`) + Pomerium services share the trace id · TC-TRC-11 sampler 0.0 (Envoy scope) |
| `tracing-journeys.spec.ts` | Browser-driven journeys through the **Jaeger UI**: TC-TRC-20 sign in → browse → search the UI → open the trace → read Envoy's `ingress:` span and Pomerium's own spans · TC-TRC-21 signing in *on* a path yields **two** traces for it — the refused 302 with the whole sign-in chain stitched in (`/.pomerium/sign_in`, `/oauth2/callback`, `/.pomerium/callback/`, all `internal:`) and the retry as its own trace · TC-TRC-22 the `traceparent` the upstream received (read off `/headers`) opens that exact trace id · TC-TRC-23 a policy-refused request → 403 page → `http.status_code=403` on the span |

## Follow-up backlog (from the QA plans, structured to slot in here)

- **Metrics TLS matrix** — `metrics_certificate[_key][_file]`: endpoint serves TLS, plain HTTP
  fails; inline and file forms interchangeable. Needs certs minted for the metrics host; note
  the aggregated handler self-scrapes Envoy over hardcoded `http://`, so `envoy_*` may drop out
  of `/metrics` under TLS — assert whatever the actual behavior is.
- **Metrics client CA** — `metrics_client_ca[_file]`: client certs required/verified; the
  **client-CA-without-server-cert is silently ignored** gap; composition with basic auth. Needs
  a second, untrusted CA — mint with `CAROOT=<suite-local dir> mkcert`.
- **Tracing protocol/endpoint matrix** — port-based protocol inference (4317→gRPC, 4318→HTTP),
  explicit `otel_exporter_otlp[_traces]_protocol`, `/v1/traces` path forms, and signal-specific
  vs generic endpoint precedence (needs a second collector container).
- **OTLP exporter headers** — `otel_exporter_otlp[_traces]_headers` reach the collector;
  entries without `=` silently dropped; traces-specific list wins. Needs a header-recording
  OTLP sink (node:22-alpine + a small mounted server.mjs, like the mcp suite's upstream).
- **Duration format rejection** — `otel_exporter_otlp_timeout: "5s"` (a duration string) must
  fail config load; these settings take integer milliseconds (`startPomeriumExpectExit`).
- **Removed legacy options** — `tracing_provider`, `tracing_sample_rate`, etc. block startup
  with per-key "config option was removed" errors.
- **Logging** — explicit all-fields access config (incl. non-defaults `ip`, `query`); authorize
  bare `headers` (all headers).
- **Shared container harness** — `setup/containers.ts`, `helpers/nav.ts` and the Playwright
  config are the third near-verbatim copy across `suites/`. The Pomerium container factory
  (image pull policy, port-release precondition, log capture) and `nav.ts` belong in
  `suites/shared/`; extracting them would also stop the two suites' readiness logic drifting.
  Deliberately not done here to avoid destabilizing the sibling suites in the same change.
- **Config validation unit tests** — `metrics_basic_auth` has no case in `config/options_test.go`
  (`Test_Validate`), so TC-MET-05 is currently its only guard. Two table cases there would cover
  the parsing deterministically and let the e2e case focus on the black-box consequence.
- **`otel_resource_attributes` inertness** — parsed but never applied to spans; document via a
  test once the header-recording sink exists.
