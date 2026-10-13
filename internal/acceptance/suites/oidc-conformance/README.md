# OIDC bridge conformance suite (containers)

Runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
(the tool behind OpenID Certification) against Pomerium's OIDC bridge
(`oidc_bridge`): the **Config OP** plan and the **Basic OP** plan, with server
metadata discovery and static client registration.

```bash
make test-oidc-conformance          # from the repo root or internal/acceptance
```

## Topology

```
 Playwright (host) ──REST──▶ conformance-server :8080  (published on 127.0.0.1:18080)
     │ browser
     ├──▶ conformance.localhost.pomerium.io:8443 ─(Pomerium route, public)─▶ conformance-server:8080
     └──▶ authenticate.localhost.pomerium.io:8443  ← OIDC bridge (the OP under test)
                │  back-channel token/userinfo/jwks calls come from conformance-server
                └──▶ keycloak.localhost.pomerium.io:8080  (Pomerium's IdP)
```

- **Keycloak** is Pomerium's identity provider (the shared acceptance realm).
- **Pomerium** is built from this source tree (`make image`), since no
  published image contains the bridge.
- **The conformance suite** (`registry.gitlab.com/openid/conformance-suite`,
  pinned release, plus MongoDB) is an ordinary upstream behind a Pomerium
  route. That route has `oidc_bridge` enabled, so the suite is also the
  bridge's relying party. Its callback is
  `https://conformance.localhost.pomerium.io:8443/test/a/pomerium/callback`,
  which is also the configured `client_id`.

Every `*.localhost.pomerium.io` name resolves to 127.0.0.1 on the host and is a
Docker network alias inside the stack, so URLs are identical on both sides.

## How a module runs

`lib/run-module.ts` acts as the human tester. It creates the module, visits each
URL the module asks for with the HTTP method it asks for, and signs in at
Keycloak when Pomerium sends the browser there. When the module asks for a
screenshot (an OP error page, or "the server must ask the user to login for a
second time"), the driver uploads one.

The driver also judges what a human reviewer would judge. A module fails if it
needed a login page and none was shown, or if `prompt=none` led to an
interactive login. A REVIEW result therefore means the driver checked the
screenshot.

## Acceptable outcomes

`fixtures/plans.ts` lists every module and what counts as a pass: PASSED or
REVIEW by default, SKIPPED only where listed (with the reason), and WARNING only
when each warning is one of `ACCEPTED_WARNINGS` (with the reason). If a suite
upgrade adds or removes modules, global setup fails until the list is updated.

The suite writes `oidc-conformance-report.md` (one row per module, with links to
the suite's log viewer) and the usual Playwright report.

## Prerequisites

- Docker, Node ≥ 22, [`mkcert`](https://github.com/FiloSottile/mkcert)
- Host ports 8443, 8080 and 18080 free. Don't run this alongside the compose
  stack or the other container suites.

## Useful knobs

| | |
|---|---|
| `BUILD_IMAGE=0 POMERIUM_IMAGE=…` | skip the image build and use an existing image |
| `CONFORMANCE_IMAGE=…` | a different conformance suite release |
| `make test-keep` | keep the containers running afterwards; browse the logs at http://127.0.0.1:18080 (`make down` removes them) |
| `OIDC_CONFORMANCE_LOGS=1` | stream container logs |
| `npx playwright test -g oidcc-prompt-login` | run a single module |
