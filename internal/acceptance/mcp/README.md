# Pomerium MCP end-to-end test suite (containers)

A container-based acceptance suite that exercises Pomerium's **MCP (Model Context
Protocol)** support end to end, the way a real client would:

- a genuine **MCP client** built on the official [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk) TypeScript SDK,
- talking to an upstream **MCP server** that is **fronted by the official `pomerium/pomerium` container** acting as an OAuth 2.1 authorization server,
- with a **real Keycloak IdP** and a **browser-driven sign-in** performed by **Playwright**.

Everything (Keycloak, the upstream MCP server, and Pomerium itself) is launched
with **[testcontainers](https://node.testcontainers.org/)**; certificates are
issued with **mkcert**.

This complements — and does not replace — the fast in-process Go suite in
`internal/mcp/e2e/`. It reuses the existing Keycloak realm (`../keycloak/`) and
the user fixtures (`../browser/fixtures/users.ts`); the Keycloak browser-login
step mirrors `../browser/helpers/authn-flow.ts` (kept local so the suite loads a
single Playwright instance — see `mcp-client/keycloak-login.ts`).

## Topology

```
 host (Playwright + MCP TS SDK)                 docker network (alias = public host)
 ─────────────────────────────────   ┌──────────────┬──────────────┬────────────────┐
 MCP client ──HTTPS:8443──▶ Pomerium  │ keycloak     │ pomerium     │ mcp-upstream   │
 Chromium   ──────────────▶ Pomerium  │ HTTP  :8080  │ HTTPS :8443  │ HTTP :8080     │
 loopback http://127.0.0.1:<cb>/cb    │ (realm:      │ (all-in-one) │ (node + MCP    │
                                      │  pomerium-e2e)│             │  SDK, mounted) │
                                      └──────────────┴──────────────┴────────────────┘
```

Each service uses a `*.localhost.pomerium.io` hostname that resolves to
`127.0.0.1` on the host **and** is a Docker network alias, with fixed, identical
ports on host and container. That makes the OIDC issuer URL byte-identical from
the browser (front-channel) and from inside Pomerium (back-channel).

Only Pomerium serves TLS (mkcert wildcard leaf for `*.localhost.pomerium.io`);
Keycloak and the upstream run plain HTTP inside the network.

## Prerequisites

- Docker (Desktop) running
- Node ≥ 22
- [`mkcert`](https://github.com/FiloSottile/mkcert): `brew install mkcert`
- Host ports **8443** and **8080** free (the acceptance docker-compose stack uses
  the same ports — don't run both at once)

The `*.localhost.pomerium.io` wildcard resolves to `127.0.0.1` via public DNS, so
no `/etc/hosts` changes are required.

## Run

```bash
cd internal/acceptance/mcp
make deps     # npm ci + playwright install chromium  (first time only)
make test         # headless
make test-headed  # watch the Keycloak sign-in in a real browser
```

`make test` generates the mkcert leaf, exports `NODE_EXTRA_CA_CERTS` so the MCP
client trusts Pomerium's TLS, then runs Playwright. The container stack is booted
in global setup and stopped in global teardown.

## What the tests cover

- **`tests/mcp-happy-path.spec.ts`** — alice (group `admins`) signs in through the
  browser; the client lists tools and calls `add(2, 3)` through Pomerium, asserting `5`.
- **`tests/mcp-enforcement.spec.ts`** — an unauthenticated request is rejected with
  `401` + `WWW-Authenticate`; charlie (group `engineering`, not `admins`) is denied
  by the route policy.

## Test users (from the reused realm; password `password123`)

| user | email | groups | MCP route (`admins`) |
|------|-------|--------|----------------------|
| alice | alice@company.com | admins, engineering | allowed |
| charlie | charlie@company.com | engineering | denied |

## Layout

```
setup/        certs.ts (mkcert), containers.ts (testcontainers), global setup/teardown
pomerium/     config.yaml mounted into the official Pomerium container
upstream/     MCP server (server.mjs) mounted into a node container as a volume
mcp-client/   OAuthClientProvider, loopback callback server, browser-auth connect()
tests/        Playwright specs
```

## Troubleshooting

- **TLS errors from the MCP client**: ensure you ran via `make test` (it sets
  `NODE_EXTRA_CA_CERTS`), and that `mkcert -CAROOT`/`rootCA.pem` exists.
- **Container logs**: run with `MCP_E2E_LOGS=1` to stream Keycloak / upstream /
  Pomerium logs, e.g. `MCP_E2E_LOGS=1 make test`.
- **Port conflicts on 8443/8080**: stop the `internal/acceptance` docker-compose
  stack (`make -C .. down`) or anything else bound to those ports.
- **Different Pomerium image**: override with `POMERIUM_IMAGE=pomerium/pomerium:vX.Y.Z make test`.
```
