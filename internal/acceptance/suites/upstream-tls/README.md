# Upstream TLS/mTLS E2E Suite

E2E tests for Pomerium's per-route [upstream TLS settings](https://www.pomerium.com/docs/reference/routes/tls)
— the TLS/mTLS connection between **Pomerium and the service behind it**,
configured via the route `tls_*` options (`tls_custom_ca` / `tls_custom_ca_file`,
`tls_client_cert` / `tls_client_key` (+ `_file`), `tls_server_name`,
`tls_upstream_server_name`, `tls_skip_verify`, `tls_upstream_allow_renegotiation`).
Exercised against the **official published Pomerium Docker image** with a real
Keycloak IdP and real, per-run OpenSSL certificate material.

The suite is **Playwright-native**, following the same architecture as the
sibling MCP and downstream-mTLS suites: `npx playwright test` is the only
entrypoint, and a Playwright global setup boots the whole container stack via
[testcontainers](https://node.testcontainers.org/) before the specs run.

|                | `internal/acceptance` (parent) | downstream-mtls | this suite |
|----------------|--------------------------------|-----------------|------------|
| Orchestration  | docker-compose                 | testcontainers  | testcontainers |
| Pomerium       | built from source              | official image  | official image (`pomerium/pomerium:main`) |
| TLS boundary   | downstream (browser → Pomerium) | downstream `downstream_mtls` | **upstream** (Pomerium → service) `tls_*` |

Everything is injected into containers as **volume mounts**: the Pomerium
config, the OpenSSL-generated certs, the Keycloak realm fixtures, and the
first-party upstream `server.js`. The realm JSON and the base server-cert
script are mounted directly from the parent suite — single source of truth,
nothing copied.

## Running

Prerequisites: **Docker and Node.js 22+**.

From `internal/acceptance`:

```sh
make deps-upstream-tls          # npm ci + Chromium + refresh the pomerium image
make test-upstream-tls          # run the suite headless
make test-upstream-tls-headed   # run with a visible browser
```

Or from this directory: `make deps` / `make test` / `make test-headed` /
`make test-debug`, or directly `npx playwright test [--headed|--debug|--ui]`.

The stack binds fixed host ports **8443** (Pomerium) and **8080** (Keycloak) —
do not run it at the same time as the parent compose stack (`make up`) or the
other container suites, which bind the same ports. `*.localhost.pomerium.io`
resolves to 127.0.0.1 and the same names are Docker network aliases, so every
URL is valid from the browser on the host and from inside the containers alike.
The upstream servers are reached only in-network (aliases `upstream`,
`upstream-tls`, `upstream-mtls`, `upstream-sni`, `upstream-reneg`); those
aliases double as each route's default SNI / verification name.

### Environment knobs

| Variable | Default | Purpose |
|----------|---------|---------|
| `POMERIUM_IMAGE` | `pomerium/pomerium:main` | Image under test (`:latest`, `git-<sha>`, … for bisecting) |
| `NODE_IMAGE` | pinned `node:22-alpine` (digest) | Base image for the echo upstreams (`server.js` is bind-mounted) |
| `VERIFY_IMAGE` | pinned `pomerium/verify` (digest) | Plain-HTTP control upstream |
| `UPSTREAM_TLS_E2E_LOGS` | unset | Stream container + cert-gen logs to the console |

testcontainers only pulls images that are missing locally; `make deps`
refreshes the rolling `pomerium:main` tag.

## How it works

`playwright.config.ts` registers `setup/global-setup.ts`, which boots (once per
run, torn down in global teardown):

1. **Certificates** (`setup/certs.ts`): a one-shot `alpine:3.21` container runs
   `scripts/gen-certs.sh`, which wraps the parent suite's server-cert script and
   then builds the upstream PKI under `.certs/upstream/` — a good CA
   (`upstream-ca`), an unrelated CA (`wrong-ca`), a client CA (`client-ca`),
   server leaves with specific SANs (`upstream-tls`, `upstream-mtls`,
   `upstream-reneg`, a `decoy.invalid` default + a `backend.internal.example.com`
   SNI cert), a client leaf (`pomerium-client`), and a standalone mismatched
   key. Idempotent — skipped while existing certs are valid. The browser ignores
   HTTPS errors, so nothing on the host needs to trust these CAs.
2. **Keycloak** (`quay.io/keycloak/keycloak`, alias
   `keycloak.localhost.pomerium.io`, host port 8080): `start-dev --import-realm`
   with the parent suite's `pomerium-e2e` realm (users alice/bob/charlie/diana,
   password `password123`).
3. **Control upstream** (`pomerium/verify`, alias `upstream`, port 8000):
   plain-HTTP; its `/json` echoes the injected `x-pomerium-claim-*` headers for
   the OIDC smoke test.
4. **Echo upstreams** (`node:alpine` + the bind-mounted `upstream/server.js`,
   port 4433): first-party TLS/mTLS servers in four modes — `tls`, `mtls`
   (requires a client cert), `sni` (switches cert on SNI), `reneg` (TLS 1.2,
   triggers server-initiated renegotiation on `/reneg`). Each answers with JSON
   describing the handshake it saw (see the security note below).
5. **Pomerium** (aliases `authenticate.localhost.pomerium.io` + every route
   host, host port 8443): the official image with one generated config
   (`setup/pomerium-config.ts` `mainConfigFile()`, written into `.gen/`) that
   holds a route per test variant, plus `.certs/` mounted read-only. Booted
   **once** in global setup (all behavior routes share the config; the specs
   select behavior by route host).

These are **user-perspective** tests. A Playwright **setup project**
(`tests/auth.setup.ts`) drives the real Keycloak login form once and saves the
browser session (`storageState`); every behavior spec then runs as that
already-authenticated user and navigates with `page.goto` (first hit to each
route subdomain SSOs silently). Every test is written as explicit `test.step`
blocks — open the route, assert the status the browser got, assert the
user-visible outcome — with the route's `from`/`to`/`tls_*` config quoted in a
comment above them, so the spec file (and the HTML report) reads as the user's
steps. A **200** with the echo JSON means the page loaded (Pomerium completed
the upstream handshake and proxied); a **503** means the handshake failed —
asserted as the rendered error page **plus** the Envoy diagnostics Pomerium
embeds in `window.POMERIUM_DATA` (`statusText` = `%RESPONSE_CODE_DETAILS%`,
`responseFlags` = `%RESPONSE_FLAGS%`). Tests run serially (`workers: 1`)
because the stack is shared and the ports are fixed. Only
`config-validation.spec.ts` is not browser-driven — it asserts Pomerium refuses
to boot on invalid config, which has no request path.

### The echo upstream and why it is safe

`pomerium/verify` has **no TLS listener**, so the mTLS-terminating upstream is a
first-party, dependency-free `upstream/server.js` (Node core modules only),
bind-mounted read-only into a stock `node:alpine`. It terminates a real
OpenSSL-backed handshake and reports, as JSON: the negotiated protocol/cipher,
the **SNI it received** (asserts `tls_server_name` / `tls_upstream_server_name`),
whether the client cert **verified** and its subject (asserts
`tls_client_cert*`), and the request headers matching `x-pomerium-claim-*`.

The header echo is an **allowlist** (`x-pomerium-claim-*` only). It never
reflects `Cookie`, `Authorization`, the `X-Pomerium-Jwt-Assertion` header, or an
arbitrary header dump — so no credential-bearing value can leak into Playwright
traces / CI artifacts. (This is the crucial difference from a `traefik/whoami`
-style upstream, which reflects every request header unconditionally.)

## Scenarios

All cases come from the manual QA test plan (Notion → QA → Test Plans → Core →
`Core.Upstream TLS`). Behavior specs navigate as the logged-in user via
`openRoute` and assert against the expectation presets in `helpers/routes.ts`
(`TLS_UNTRUSTED_CA` / `TLS_SAN_MISMATCH` / `UPSTREAM_TERMINATED`): a **200**
with the echo JSON means Pomerium completed the upstream handshake and proxied;
a **503** (Envoy local reply) means it failed, with the rendered error page and
the `window.POMERIUM_DATA` diagnostics asserted per failure shape.

| Spec file | Coverage |
|---|---|
| `smoke.spec.ts` | Scaffolding proof: real Keycloak OIDC login through the plain-HTTP control route (identity headers injected); then identity headers **and** Pomerium's client cert reaching the mTLS upstream (`tls_custom_ca` + `tls_client_cert_file`), asserted from the echo JSON |
| `custom-ca.spec.ts` | `tls_custom_ca` (base64) + `tls_custom_ca_file` happy paths; unrelated CA → 503; no CA → 503 (private CA untrusted by system roots) |
| `client-cert.spec.ts` | `tls_client_cert`+`tls_client_key` (inline) and the `_file` pair authenticate to the mTLS upstream (verified subject `pomerium-client`); no client cert → 503 |
| `server-name.spec.ts` | `tls_server_name` and `tls_upstream_server_name` drive SNI + verification (200, asserting the SNI the upstream received); bogus name → 503; **precedence**: `tls_upstream_server_name` wins over `tls_server_name` |
| `skip-verify.spec.ts` | `tls_skip_verify` off → 503 (untrusted + name mismatch); on → 200; skip overrides a (wrong) `tls_custom_ca` |
| `renegotiation.spec.ts` | `tls_upstream_allow_renegotiation`: server-initiated renegotiation refused (503) when unset, permitted (200) when true — the positive case asserts the upstream's `renegotiated: true` marker, so a quiet 200 that never renegotiated cannot false-pass; normal requests proxy either way |
| `config-validation.spec.ts` | Boot-time config errors: cert without key (and `_file`); mismatched inline pair; mismatched file pair; `tls_custom_ca_file` missing path |

### Behavior gotchas encoded in the specs

- **Default SNI / verification name is the `to` hostname.** The SNI upstream
  serves the `backend.internal.example.com` cert only when the client sends that
  exact SNI, so a route verifies only when `tls_server_name` /
  `tls_upstream_server_name` set both the SNI and the verification name to it.
- **`tls_custom_ca` replaces the trust bundle** for the route (does not append
  to system roots), so a route without it fails against the private upstream CA.
- **`tls_skip_verify` wins over `tls_custom_ca`** — verification is short-circuited.
- Renegotiation is a **TLS 1.2** concept; the reneg upstream is pinned to 1.2.
- **What the browser sees on an upstream TLS failure** (pinned from real runs;
  the `helpers/routes.ts` presets match these structurally): Envoy answers with
  a 503 local reply rendered as Pomerium's error page, embedding its
  diagnostics in `window.POMERIUM_DATA`. Untrusted/unrelated CA →
  `upstream_reset_before_response_started{remote_connection_failure|TLS_error:…unable_to_get_local_issuer_certificate…}`,
  flag `UF`. Verification-name (SAN) mismatch → same shape but naming the
  `SAN_matcher` and the served cert's SANs. mTLS upstream that never got a
  client cert (TLS 1.3: its `certificate_required` alert arrives post-handshake)
  and a refused renegotiation → plain `…{connection_termination}`, flag `UC`.
- **Two error-page variants.** The UI renders the branded "Web Server is down"
  upstream page only when `statusText` contains "upstream" and **not** "local"
  (`ui/src/App.tsx`); BoringSSL's `unable_to_get_local_issuer_certificate`
  detail trips that heuristic, so untrusted-CA failures render the generic
  error page instead. Both variants render the Envoy detail itself, which is
  what `TLS_UNTRUSTED_CA.pageText` asserts.
- **The reneg upstream reports whether renegotiation actually happened**: on
  `/reneg` it answers `renegotiated: true` only after the second handshake
  completes, and `renegotiated: false` (instead of hanging) when it could not
  initiate one.
- Config-validation containers bind **no host port**, so they never contend for
  8443 with the healthy shared instance.

## Extension points

To add a scenario, add a route to `mainRoutes()` (`setup/pomerium-config.ts`)
with the `tls_*` options under test and an entry in `ROUTE_HOSTS`
(`setup/constants.ts`), then write the spec as explicit `test.step` blocks:
`openRoute` (`helpers/routes.ts`) to navigate as the logged-in user, then
assert the echo JSON (200 paths) or the error page via an
`UpstreamErrorExpectations` preset (503 paths). A scenario needing its own
(e.g. invalid) config uses `generateConfig(...)` directly — see
`config-validation.spec.ts`.

## Debugging

- `npx playwright test --headed`, `--debug` (inspector) or `--ui` work directly.
- `playwright-report/index.html` — HTML report; `test-results/` — traces,
  screenshots, videos (retained on failure).
- `UPSTREAM_TLS_E2E_LOGS=1` streams Keycloak/Pomerium/upstream/cert-gen output live.
- Certificates persist in `.certs/` between runs (regenerated when expired);
  `make clean` removes them and the generated `.gen/` configs.
