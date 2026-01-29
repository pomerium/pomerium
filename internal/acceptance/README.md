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

## CI

Workflow lives in `.github/workflows/acceptance.yaml` and installs Node, Go, and Playwright dependencies. Artifacts are collected under `internal/acceptance/artifacts/`.

## Troubleshooting

- User not found: ensure `RUN_ID` matches between `seed-keycloak.sh` and tests.
- Services unhealthy: `make status` then `make logs`.
- Auth redirects fail: verify DNS resolves `*.localhost.pomerium.io` to 127.0.0.1 and check cert generation in `internal/acceptance/certs/`.
- Playwright output: `make report`.
