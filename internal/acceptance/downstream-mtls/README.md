# Downstream mTLS E2E Suite

E2E tests for Pomerium's global [`downstream_mtls` settings](https://www.pomerium.com/docs/reference/downstream-mtls-settings)
(client certificate requirements for end users), exercised against the
**official published Pomerium Docker image** with a real Keycloak IdP and a
real browser.

The suite is **Playwright-native**, following the same architecture as the
sibling MCP suite (`internal/acceptance/mcp`): `npx playwright test` is the
only entrypoint, and a Playwright global setup boots the whole container stack
via [testcontainers](https://node.testcontainers.org/) before the specs run.
It complements the parent acceptance suite with a different harness:

|                     | `internal/acceptance` (parent) | this suite |
|---------------------|--------------------------------|------------|
| Orchestration       | docker-compose                 | testcontainers (from Playwright global setup) |
| Pomerium            | built from source              | official image (`pomerium/pomerium:main`) |
| mTLS coverage       | deprecated per-route `tls_downstream_client_ca_file` | global `downstream_mtls` + IdP login combined |

Everything is injected into containers as **volume mounts**: the Pomerium
config, the OpenSSL cert-gen script and the Keycloak realm fixtures. Shared
assets (cert scripts, realm JSON) are mounted directly from the parent suite -
single source of truth, nothing copied.

## Running

Prerequisites: **Docker and Node.js 22+**.

From `internal/acceptance`:

```sh
make deps-downstream-mtls          # npm ci + Chromium + refresh the pomerium image
make test-downstream-mtls          # run the suite headless
make test-downstream-mtls-headed   # run with a visible browser
```

Or from this directory: `make deps` / `make test` / `make test-headed` /
`make test-debug`, or directly `npx playwright test [--headed|--debug|--ui]`.

The stack binds fixed host ports **8443** (Pomerium) and **8080** (Keycloak) -
do not run it at the same time as the parent compose stack (`make up`) or the
MCP suite, which bind the same ports. `*.localhost.pomerium.io` resolves to
127.0.0.1 and the same names are Docker network aliases, so every URL is valid
from the browser on the host and from inside the containers alike.

### Environment knobs

| Variable | Default | Purpose |
|----------|---------|---------|
| `POMERIUM_IMAGE` | `pomerium/pomerium:main` | Image under test (`:latest`, `git-<sha>`, ... for bisecting) |
| `MTLS_E2E_LOGS` | unset | Stream container + cert-gen logs to the console |
| `CERTS_DIR` | `.certs/mtls` | Override the client-cert location used by the specs |

testcontainers only pulls images that are missing locally; `make deps`
refreshes the rolling `pomerium:main` tag.

## How it works

`playwright.config.ts` registers `setup/global-setup.ts`, which boots (once per
run, torn down in global teardown):

1. **Certificates** (`setup/certs.ts`): a one-shot `alpine:3.21` container runs
   `scripts/gen-certs.sh`, a thin wrapper over the parent suite's OpenSSL
   scripts. Produces the Pomerium server cert plus an mTLS root CA, an
   intermediate CA, and client certs (valid / intermediate-signed /
   untrusted-CA) under `.certs/`. Idempotent - skipped while existing certs
   are valid. Unlike the MCP suite this does NOT use mkcert: downstream mTLS
   needs a client-cert PKI (second untrusted CA, intermediate chain) that
   mkcert cannot produce, and the browser ignores HTTPS errors so no host
   trust is needed.
2. **Keycloak** (`quay.io/keycloak/keycloak`, alias
   `keycloak.localhost.pomerium.io`, host port 8080): `start-dev
   --import-realm` with the parent suite's `pomerium-e2e` realm (users
   alice/bob/charlie/diana, password `password123`).
3. **Upstream** (`traefik/whoami`, alias `upstream`): echoes request headers,
   which makes Pomerium's injected identity headers assertable.
4. **Pomerium** (aliases `authenticate.localhost.pomerium.io`,
   `mtls.localhost.pomerium.io`, host port 8443): the official image with
   `pomerium/config.yaml` and `.certs/` mounted read-only.

Tests run serially (`workers: 1`) because the stack is shared and the ports
are fixed.

## Scenarios

`tests/downstream-mtls.spec.ts` — the original browser smoke specs (base
config, default enforcement): valid cert + Keycloak login → 200 with
`X-Pomerium-Claim-Email` echoed; no cert → **HTTP 495**; untrusted CA → 495;
`/healthz` exempt.

The remaining spec files implement the **Client Certificates (mTLS) automated
test plan** (Notion → QA → Test Plans → Core → `Core.Client Certificates`).
Most cases boot their own Pomerium configuration via `startPomerium` +
`setup/pomerium-config.ts`; non-browser cases use Playwright's request API
(`helpers/api.ts`) and raw `node:tls` probes (`helpers/raw-tls.ts`).

| Test case | Spec file | Coverage |
|---|---|---|
| TC-CC-01..04 | `error-handling.spec.ts` | 495 + no IdP redirect for untrusted/absent certs; no mTLS mention when disabled; `client-certificate-required` vs `invalid-client-certificate` deny reasons (authorize logs) |
| TC-CC-05..08 | `ca-config.spec.ts` | trust root via `ca_file` / `ca` / `DOWNSTREAM_MTLS_CA_FILE` / `DOWNSTREAM_MTLS_CA` |
| TC-CC-09..11 | `crl.spec.ts` | revoked leaf rejected via `crl_file` / `crl` / both env vars; leaf-issuer-only CRL semantics (see deviation below) |
| TC-CC-12..14 | `enforcement.spec.ts` | `policy_with_default_deny` (internal pages exempt), `policy` (+ explicit `invalid_client_certificate` deny rule), `reject_connection` (TLS-handshake rejection, all routes, no authorize logs) |
| TC-CC-15 | `san-matching.spec.ts` | `match_subject_alt_names` per SAN type (dns/email/ip_address/uri) + non-matching rejection |
| TC-CC-16 | `verify-depth.spec.ts` | `max_verify_depth` ∈ {default(1), 2, 3, 0=unlimited} + env var |
| TC-CC-17..18 | `cert-headers.spec.ts` | `$pomerium.client_cert_fingerprint`, `client_cert_san_dns`, `client_cert_san_email` request headers (the only supported variables) |
| TC-CC-19..20 | `ppl-client-certificate.spec.ts` | PPL `client_certificate` by fingerprint list and fingerprint+`spki_hash`, with real Keycloak sign-in (unlisted trusted cert → 403, not 495) |

**Deviation from the manual plan (TC-CC-10):** the plan expected a CRL for any
CA in the chain to require CRLs for all CAs. The implementation deliberately
checks the **leaf's direct issuer only** (`OnlyVerifyLeafCertCrl` in
`config/envoyconfig/tls.go`; mirrored in `authorize/evaluator/functions.go`),
so partial CRL coverage is allowed and the spec asserts that contract.

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

To add a scenario with its own Pomerium configuration, generate it with
`generateConfig(...)` (`setup/pomerium-config.ts`) and boot it via
`startPomerium(...)` in the spec's `beforeAll` (or per test) - see any of the
test-plan spec files for the pattern. Ideas not yet covered:

- PPL `client_certificate` SAN matchers (`san_dns` / `san_email` / `san_uri`).
- CRL freshness under `reject_connection` (`thisUpdate`/`nextUpdate` expiry).
- Multiple trusted client CAs in one bundle.
- Browser-facing UX of the 495 error page (screenshot/content assertions).

## Debugging

- `npx playwright test --headed`, `--debug` (inspector) or `--ui` work
  directly - the stack boots either way.
- `playwright-report/index.html` - HTML report; `test-results/` - traces,
  screenshots, videos (retained on failure).
- `MTLS_E2E_LOGS=1` streams Keycloak/Pomerium/cert-gen output live.
- The stack is reachable from the host while tests run:
  `curl -k https://mtls.localhost.pomerium.io:8443/healthz`.
- Certificates persist in `.certs/` between runs (regenerated when expired);
  `make clean` removes them.
