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

End-to-end behavior (real browser sign-in):

- **`tests/mcp-happy-path.spec.ts`** — alice (group `admins`) signs in through the
  browser; the client lists tools and calls `add(2, 3)` through Pomerium, asserting `5`.
- **`tests/mcp-enforcement.spec.ts`** — an unauthenticated request is rejected with
  `401` + `WWW-Authenticate`; charlie (group `engineering`, not `admins`) is denied
  by the route policy.

### MCP 2025-11-25 spec conformance (downstream authorization server)

These verify that the official `pomerium/pomerium` image, acting as the OAuth 2.1
authorization server in front of an MCP resource, conforms to the
[MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
authorization spec, and cover the downstream-side items from the *MCP: remote
upstreams* project (ENG-3638 test plan).

| Spec file | Covers | Issue / spec |
|-----------|--------|--------------|
| `spec-as-metadata.spec.ts` | PRM (RFC 9728) + AS metadata shape: `code_challenge_methods_supported=[S256]`, `registration_endpoint`, `client_id_metadata_document_supported`, response/grant types | MCP 2025-11-25 §Authorization |
| `spec-www-authenticate.spec.ts` | 401 `WWW-Authenticate` carries a `resource_metadata` URI that round-trips; root has no trailing slash | ENG-3638 R1–R6 |
| `spec-prm-normalization.spec.ts` | PRM `resource` path normalization: root, sub/nested paths, trailing-slash strip, `//`→`/` | ENG-3638 P1–P10 |
| `spec-protocol.spec.ts` | client/server negotiate `protocolVersion 2025-11-25` through Pomerium; `MCP-Protocol-Version` forwarded | MCP 2025-11-25 transport |
| `spec-dcr.spec.ts` | Dynamic Client Registration returns an opaque `client_id`; malformed metadata → 400 `invalid_client_metadata` | RFC 7591 |
| `spec-security.spec.ts` | **PKCE cannot be bypassed with empty challenge/verifier** (hard-fail); auth codes single-use; loopback redirect port ignored | **ENG-3976**, ENG-3857 |
| `spec-tools.spec.ts` | `tools/list`, structured (`outputSchema`) output, invalid-input → tool error (SEP-1303), tool-level policy denial (`mcp_tool`) | MCP 2025-11-25 tools |

Quarantined (`test.fixme` / `test.skip`, documented in-file): `%2F` path preservation
(Envoy normalizes before the route — ENG-4094), invalid-`Origin` 403 (the MCP *server's*
responsibility, not the proxy), and negative `expires_in` (ENG-3982, needs expired-session
timing). As of `pomerium:main` the PKCE-bypass (ENG-3976) and loopback-port (ENG-3857)
checks **pass** — those bugs are fixed there.

### Not covered here (container-only boundary)

`InsecureSkipMCPMetadataSSRFCheck` is code-only, so the official image always blocks
metadata fetches to internal hosts. That makes **CIMD**, the **remote-upstream OAuth**
flow (the core of *MCP: remote upstreams* — Linear/Notion/etc.), and the
`mcp_allowed_as_metadata_domains` matrix (ENG-3638 A/B/C/D) **not automatable in this
suite** — they need in-process Go tests. This suite covers the *downstream* side only.

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
