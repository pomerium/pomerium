# Downstream mTLS E2E Suite

E2E tests for Pomerium's global [`downstream_mtls` settings](https://www.pomerium.com/docs/reference/downstream-mtls-settings)
(client certificate requirements for end users), exercised against the
**official published Pomerium Docker image** with a real Keycloak IdP and a
real browser.

This suite complements the parent acceptance suite with a different harness:

|                     | `internal/acceptance` (parent) | this suite |
|---------------------|--------------------------------|------------|
| Orchestration       | docker-compose                 | testcontainers-go |
| Pomerium            | built from source              | official image (`pomerium/pomerium:main`) |
| Playwright          | on the host (npm)              | in a container, specs bind-mounted |
| mTLS coverage       | deprecated per-route `tls_downstream_client_ca_file` | global `downstream_mtls` + IdP login combined |

Everything is injected into containers as **volume mounts**: the Pomerium
config, the OpenSSL cert-gen script, the Keycloak realm fixtures and the
Playwright specs. Shared assets (cert scripts, realm JSON) are mounted
directly from the parent suite - single source of truth, nothing copied.

## Running

Prerequisites: **Docker and Go**. No host node/npm/openssl needed for the
default (containerized) mode; headed/host mode additionally needs Node.js 22+.

From `internal/acceptance`:

```sh
make deps-downstream-mtls          # pull images (refreshes pomerium:main), install browser deps
make test-downstream-mtls          # run the suite (Playwright in a container)
make test-downstream-mtls-headed   # run with a visible browser (Playwright on the host)
```

Or from this directory: `make deps` / `make test` / `make test-headed` /
`make test-host` (host-run Playwright, headless), or directly
`go test -tags e2e -v -timeout 30m ./...`.

First run pulls images (Playwright ~2 GB, Keycloak ~450 MB, Pomerium ~120 MB).
The test itself only pulls images that are missing locally, so run
`make deps-downstream-mtls` to refresh the rolling `pomerium:main` tag.
The suite is opt-in via the `e2e` build tag and never runs as part of
`go test ./...` or the parent `acceptance` tag.

### Headed / host mode

A visible browser cannot run inside the Linux Playwright container, so
`test-headed` (env `E2E_HEADED=1`, or `E2E_PLAYWRIGHT_MODE=host` for headless)
runs the same specs with `npx playwright test` on the host against the same
containerized stack. In this mode Pomerium and Keycloak are published on fixed
host ports **8443** and **8080** (`*.localhost.pomerium.io` resolves to
127.0.0.1, so all URLs are identical to container mode). Those ports must be
free - stop the parent acceptance compose stack first if it is running.

### Environment knobs

| Variable | Default | Purpose |
|----------|---------|---------|
| `POMERIUM_IMAGE` | `pomerium/pomerium:main` | Image under test (`:latest`, `git-<sha>`, ... for bisecting) |
| `KEYCLOAK_IMAGE` | `quay.io/keycloak/keycloak:26.5.2` | IdP image |
| `UPSTREAM_IMAGE` | `traefik/whoami:v1.11` | Upstream echo server |
| `PLAYWRIGHT_IMAGE` | `mcr.microsoft.com/playwright:v1.61.1-noble` | Runner; **must match** the `@playwright/test` pin in `browser/package.json` - bump them together (`make lockfile` after) |
| `E2E_KEEP_ARTIFACTS` | unset | Keep the per-run workspace even on success |

## How it works

One Go test (`e2e_test.go`) stands up, on a dedicated Docker network:

1. **cert-gen** (one-shot `alpine:3.21`): runs `scripts/gen-certs.sh`, a thin
   wrapper over the parent suite's OpenSSL scripts. Produces the Pomerium
   server cert plus an mTLS root CA, an intermediate CA, and client certs
   (valid / intermediate-signed / untrusted-CA) in the run workspace.
2. **keycloak** (alias `keycloak.localhost.pomerium.io`): `start-dev
   --import-realm` with the parent suite's `pomerium-e2e` realm (users
   alice/bob/charlie/diana, password `password123`).
3. **upstream** (`traefik/whoami`, alias `upstream`): echoes request headers,
   which makes Pomerium's injected identity headers assertable.
4. **pomerium** (aliases `authenticate.localhost.pomerium.io`,
   `mtls.localhost.pomerium.io`): the official image with
   `pomerium/config.yaml` and the generated certs mounted read-only.
5. **playwright runner**: `browser/` is mounted read-only, copied to `/work`,
   `npm ci && npx playwright test`. Reports/traces are written to the mounted
   `/artifacts` directory.

All browser traffic stays inside the Docker network (fixed port `:8443`,
matching the realm's redirect URIs), resolved via network aliases.

## Scenarios (`browser/tests/downstream-mtls.spec.ts`)

Enforcement mode under test: `policy_with_default_deny` (the default).

1. Valid client cert + Keycloak login → upstream responds 200 and echoes
   `X-Pomerium-Claim-Email: alice@company.com` (mTLS + OIDC + identity
   headers, end to end).
2. No client cert → **HTTP 495** error page, no IdP redirect.
3. Client cert from an untrusted CA → HTTP 495.
4. `/healthz` without a cert → 200 (control-plane routes are exempt from the
   default deny).

### Behavior gotchas encoded in the specs

- Under `policy` / `policy_with_default_deny`, Envoy is configured with
  `TrustChainVerification: ACCEPT_UNTRUSTED`: the TLS handshake **succeeds**
  even with a missing or untrusted client cert, and enforcement happens in the
  authorize service (HTTP 495 + HTML error page, *before* any login
  redirect). TLS-level rejection only happens under
  `enforcement: reject_connection`.
- `downstream_mtls.ca_file` is the **root CA only**, not the chain bundle:
  `max_verify_depth` (default 1) counts chain certificates excluding the trust
  anchor, and any cert in the CA bundle can act as an anchor - with the chain
  bundle mounted, depth semantics would be untestable.

## Extension points

- `enforcement: reject_connection`: expect `page.goto` to reject with
  `net::ERR_SSL_CLIENT_AUTH_*` (see `isTLSHandshakeError` in
  `browser/helpers/mtls.ts`). **Note:** the Go-side `/healthz` wait must then
  present a client certificate via `tls.Config.Certificates`, or switch to
  `wait.ForListeningPort("8443/tcp").SkipInternalCheck()` (the distroless
  image has no `/bin/sh` for the internal check).
- `enforcement: policy` + a route-level `deny` rule with
  `invalid_client_certificate`.
- `max_verify_depth: 2` with the pre-generated intermediate-signed client
  cert (`client-chain-full.crt`).
- `match_subject_alt_names` (the valid client cert carries SAN
  `email:alice@company.com` and `DNS:alice.company.com`).
- PPL `client_certificate` criteria (`fingerprint` is pre-computed in
  `certs/mtls/client-valid.fingerprint`).
- CRL revocation via `crl_file`.

Each of these needs its own Pomerium container/config variant; add a config
under `pomerium/` and a spec under `browser/tests/`.

## Debugging

- The per-run workspace `artifacts/run-<ts>/` (kept on failure) contains:
  - `logs/pomerium.log`, `logs/keycloak.log` - full container logs
  - `playwright/report/index.html` - Playwright HTML report
  - `playwright/test-results/` - traces, screenshots, videos
  - `certs/` - all generated certificates
- Playwright output streams live into `go test -v`.
- The Pomerium host-mapped port is logged at startup
  (`*.localhost.pomerium.io` resolves to `127.0.0.1`, so you can curl it from
  the host; the full login flow only works in-network, though, because
  redirects use port 8443).
- Using colima/podman instead of Docker Desktop: you may need
  `TESTCONTAINERS_RYUK_DISABLED=true`; container cleanup is handled by the
  test itself, Ryuk is the safety net.
