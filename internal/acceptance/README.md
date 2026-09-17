# E2E Acceptance Harness (Operator Guide)

This harness runs real Keycloak + Playwright against Pomerium to validate the critical auth path (authn, authz, cookies, headers, WebSocket/CORS, and reserved endpoints).

## Source of truth

- `internal/acceptance/docker-compose.yml`: service topology and health checks.
- `internal/acceptance/pomerium/config.yaml`: routes, policies, headers, and mTLS config.
- `internal/acceptance/keycloak/realm.json`: IdP realm, clients, mappers, and token lifetimes.
- `internal/acceptance/fixtures/users.json`: test users (used by tests and `seed-keycloak.sh`).
- `internal/acceptance/browser/fixtures/test-data.ts`: URLs, routes, timeouts.
- `internal/acceptance/browser/tests/`: test suites (authn/authz/headers).
- `internal/acceptance/scripts/`: operational scripts (seed, certs, wait, artifacts).
- `internal/acceptance/ws-server/`: WebSocket echo server used in WS tests.

## Prerequisites (local)

- Docker + Docker Compose
- Node (see `.tool-versions` or `internal/acceptance/browser/package.json`)
- `jq` (only needed if running `scripts/seed-keycloak.sh` directly on the host)

The `*.localhost.pomerium.io` domains resolve to `127.0.0.1` via public DNS, so no `/etc/hosts` entries are required.

## Quick start

```bash
# From internal/acceptance
make deps
make test
```

`make test` starts the stack, waits for readiness, seeds users, and runs Playwright.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Actions Runner                     │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Playwright  │───▶│   Pomerium   │───▶│   Keycloak   │  │
│  │ Test Runner  │    │  (from src)  │◀───│    (IdP)     │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   │                               │
│         │                   ▼                               │
│         │            ┌──────────────┐                       │
│         └───────────▶│   Upstream   │                       │
│     validate cookies │ (verify app) │                       │
│     redirects,headers└──────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

## Common operations

```bash
# Start/stop the stack
make up
make down

# Wait for services (optional; compose uses health checks)
make wait

# Run tests
make test
make test-mode-headed
make test-mode-debug
make test-suite-authn
make test-suite-authz
make test-suite-headers
# Legacy aliases still work: `make test-headed`, `make test-debug`, `make test-authn`, `make test-authz`, `make test-headers`.

# Reports and artifacts
make report
make artifacts

# Logs and status
make logs
make status
```

## Configuration and fixtures

- Edit user data in `internal/acceptance/fixtures/users.json`.
- Update policies and routes in `internal/acceptance/pomerium/config.yaml`.
- Update Keycloak token lifetimes or mappers in `internal/acceptance/keycloak/realm.json`.
- Update URLs and timeouts in `internal/acceptance/browser/fixtures/test-data.ts`.

## Hosted authenticate suite (`browser/tests/hosted/`)

Automates the QA test plan cases for both hosted-authenticate flavors against
the REAL cloud service `https://authenticate.pomerium.app`:

- **New HA** (`idp_provider: hosted` + local authenticate) - `pomerium-hosted-new`
  (`:8444`, `pomerium/config-hosted-new.yaml`)
- **Old HA** (stateless flow, `authenticate_service_url: https://authenticate.pomerium.app`) -
  `pomerium-hosted-old` (`:8445`, `cookie_expire: 90s` for the session-timeout test)
- **Priority** (hosted URL + a full Keycloak IdP block; hosted must win) -
  `pomerium-hosted-priority` (`:8446`)

These services sit behind the `hosted` compose profile and the specs are gated
on `HOSTED_E2E=1`, so the default `make test` / PR CI never starts them and
reports every hosted test as skipped.

```bash
# everything that needs no account (redirect shapes, invalid/empty creds, priority):
make test-suite-hosted

# full suite - positive login/logout/timeout tests need a real hosted-IdP account:
HOSTED_TEST_EMAIL='qa@example.com' HOSTED_TEST_PASSWORD='...' make test-suite-hosted
```

Notes:

- Requires outbound internet; `global-setup.ts` fails fast with a named check
  when the cloud service is unreachable.
- Tests that log in are serialized (`--workers=1`) and only ever use the real
  account for positive paths; invalid-credential tests use random fake emails,
  so the account cannot be locked out.
- `HA.Google single-sign.positive` from the QA plan is intentionally NOT
  automated (real Google login cannot be driven by automation) - manual only.
- All selectors, copy strings, and captured live-UI facts for the cloud
  sign-in and sign-out UI live in `browser/helpers/hosted.ts` only (see its
  module header). If the hosted UI changes, re-capture with
  `cd browser && npx playwright codegen --ignore-https-errors
  https://verify-hosted.localhost.pomerium.io:8444` and update that one file.

## CI

Workflow lives in `.github/workflows/acceptance.yaml` and installs Node, Go, and Playwright dependencies. Artifacts are collected under `internal/acceptance/artifacts/`.

## Troubleshooting

- Services unhealthy: `make status` then `make logs`.
- Auth redirects fail: verify DNS resolves `*.localhost.pomerium.io` to 127.0.0.1 and check cert generation in `internal/acceptance/certs/`.
- Playwright output: `make report`.
