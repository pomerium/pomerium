# JWT Identity Providers — change plan

**Status:** Design proposal, ready for review
**Author:** Denis Mishin (`dmishin@pomerium.com`)
**Date:** 2026-05-25
**Branch:** `wasaga/poc-accept-k8s-token`
**Supersedes:** the POC in this branch (the `idp_provider: jwt` global flag and
related `extjwt`-as-global-provider plumbing)
**References:**
[`docs/k8s-sa-token-research.md`](./k8s-sa-token-research.md)

---

## 1. Problem

The current POC ships a verify-only `"jwt"` identity provider, but it slots
into the **global** `idp_provider` config slot. Three structural problems fall
out of that:

1. **Interactive sign-ins break for the whole deployment.** Setting
   `idp_provider: jwt` makes `authenticator.SignIn` return `ErrNotSupported`,
   so any browser route 500s.
   ([Review finding #2](#)).
2. **Audience scoping lives on the wrong object.** Audiences are a per-
   recipient concern (this route accepts tokens whose `aud` is X), but the
   POC attaches them to the global IdP — and the per-policy override is dead
   code ([Review finding #3](#)).
3. **One IdP per deployment.** A Pomerium that fronts both an EKS workload
   (Kubernetes SA tokens) and a GitLab runner (CI JWTs) cannot serve both
   trust roots through the current single-IdP model.

The conceptual error: the POC conflated *"the IdP used for browser SSO"* with
*"an issuer Pomerium will accept JWTs from."* These are separate concerns and
need separate config surfaces.

## 2. Goals

- Keep the existing OIDC browser-SSO IdP fully functional and unchanged.
- Allow Pomerium to accept JWT bearer tokens from **multiple named issuers**
  on **specific routes** that explicitly opt in.
- Audience binding is **mandatory** and lives **on the route**, not on the IdP.
- Composition with the rest of Pomerium (PPL, audit logs, downstream JWT
  injection, session storage) stays uniform — JWT-authenticated sessions
  look like any other session from the policy layer's perspective.
- Verifier code itself (signature, `iss`, `exp`, JWKS caching) is reusable from
  the POC; only the wiring changes.

## 3. Non-goals

- TokenReview API integration (deferred — pure JWT verification only for now).
- Refresh, revocation, or any OAuth2-flow methods for JWT IdPs.
- Backwards compatibility with the POC's `idp_provider: jwt` global option —
  the POC is unreleased; we deprecate it before it ships.
- Per-IdP claim mapping. PPL `claim/...` already references raw verified
  claims; no rewrite layer is needed.
- Synthetic Kubernetes claims (the POC's `enrichKubernetesClaims`). Policies
  can match `claim/kubernetes.io.namespace` directly.

## 4. Design

### 4.1 Two-tier IdP model

| Tier | Configured at | Purpose | Methods used |
|---|---|---|---|
| Browser IdP | `idp_provider` (existing) | Interactive sign-in, cookie sessions, refresh, dashboard | `SignIn`, `Authenticate`, `Refresh`, `UpdateUserInfo`, `SignOut` |
| JWT IdPs | `jwt_identity_providers` (new, global list) | Verify externally-issued JWTs presented in `Authorization: Bearer` headers | `VerifyIdentityToken` only |

The browser IdP is exactly what we have today. JWT IdPs are new and are
defined as a list of named verifier configurations.

### 4.2 Config shape

```yaml
# Existing browser IdP — unchanged
idp_provider: oidc
idp_provider_url: https://login.example.com
idp_client_id: ...
idp_client_secret: ...

# NEW: globally declared, verify-only JWT issuers
jwt_identity_providers:
  - name: k8s-prod
    issuer: https://oidc.eks.us-west-2.amazonaws.com/id/ABC
    jwks_url: ""                       # optional override, e.g. for private clusters
    supported_algs: [RS256]            # explicit allowlist; default = RS256+ES256+EdDSA
  - name: github-actions
    issuer: https://token.actions.githubusercontent.com

routes:
  # Browser-only route — unchanged
  - from: https://app.example.com
    policy: ...

  # M2M-only route — references a JWT IdP, scoped to a specific audience
  - from: https://api.example.com
    accept_jwt_idps:
      - name: k8s-prod
        audiences: [pomerium.api]      # MANDATORY; non-empty
    policy:
      - allow:
          and:
            - claim/sub: "system:serviceaccount:platform:api-client"

  # Multi-issuer route — accepts tokens from either trust root
  - from: https://mixed.example.com
    accept_jwt_idps:
      - name: k8s-prod
        audiences: [pomerium.mixed]
      - name: github-actions
        audiences: [pomerium.ci]
    policy: ...
```

### 4.3 Resolution flow for an incoming request

```
HTTP request arrives at route R
  │
  ├─ has cookie session AND Authorization: Bearer ?
  │     → 400 Bad Request  (decision #6 — mutually exclusive trust contexts)
  │
  ├─ has Authorization: Bearer ?
  │     │
  │     ├─ does R have accept_jwt_idps? 
  │     │     → no  : 401 (decision #7 — bearer present but no JWT IdP configured)
  │     │     → yes : parse JWT, extract `iss`
  │     │            │
  │     │            ├─ does any accept_jwt_idps[].name resolve to a 
  │     │            │   jwt_identity_providers entry whose `issuer` 
  │     │            │   matches the JWT's `iss`?
  │     │            │     → no  : 401
  │     │            │     → yes : verify signature/exp/nbf against that 
  │     │            │             provider's JWKS; check `aud` ∩ 
  │     │            │             accept_jwt_idps[].audiences is non-empty
  │     │            │
  │     │            └─ on success: create/find verify-only session 
  │     │                           keyed by (jwt_idp_name, token-uuid); 
  │     │                           proceed to PPL evaluation
  │     │
  │     └─ on any failure : 401
  │
  ├─ has cookie session ?
  │     → standard cookie/OIDC path, unchanged
  │
  └─ no auth at all ?
        │
        ├─ R has accept_jwt_idps configured ?
        │     → 401  (decision #1 — never fall through to browser SSO for M2M routes)
        │
        └─ otherwise : redirect to browser SSO
                       (existing behavior; unchanged)
```

### 4.4 Session model

JWT-bearer-authenticated sessions:

- Stored in the databroker like any other session.
- `s.RefreshDisabled = true` (already true in current POC).
- `s.OauthToken = nil` (no refresh path possible).
- Session ID = UUIDv5 derived from `(jwt_idp_name, raw_token)` so the same
  token presented twice hits the same cached session.
- All claims from the verified JWT are flattened and attached via
  `session.AddClaims(...)` — exactly as today.
- Downstream signed assertion: Pomerium mints its own JWT
  (`X-Pomerium-Jwt-Assertion`) from the session as it does for any session
  (decision #5 — downstream upstreams never see the source JWT).

### 4.5 What gets removed

- The global `idp_provider: jwt` shortcut. `extjwt.Provider` is no longer
  registered in the global `identity.RegisterAuthenticator(...)` registry.
  It becomes an internal type owned by the JWT-IdP resolver.
- `enrichKubernetesClaims` (decision #3). Policies use raw claims:
  ```yaml
  - allow:
      and:
        - claim/kubernetes.io.namespace: "platform"
  ```
  No more synthesized `groups` / `k8s.namespace` claims, no cross-issuer
  spoofing surface.
- `Options.IDPIdentityTokenAllowedAudiences`, `Policy.IDPIdentityTokenAllowedAudiences`,
  and the proto fields they map to. Audiences live on the route's
  `accept_jwt_idps` entry exclusively.
- `Options.IDPJWKSURL`. JWKS URL lives on the named `jwt_identity_providers`
  entry exclusively.
- `BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN` usage from the
  POC. The presence of `accept_jwt_idps` IS the opt-in signal (decision #7).
  The enum value itself can stay for other uses, but the resolver no longer
  consults it for JWT IdP routing.

### 4.6 What stays from the POC

- The signature/`iss`/`exp`/`nbf` verification core in
  `pkg/identity/oidc/extjwt/extjwt.go` (it's an `Authenticator`-shaped wrapper
  around `go-oidc` that works correctly).
- The integration test patterns (testenv-based + k3s testcontainers).
- The `mockidp.SignJWT` test helper.

## 5. Decisions (from this review round)

| # | Question | Decision | Rationale |
|---|---|---|---|
| 1 | Mixed-mode (no bearer present on a JWT-only route) — 401 or browser-fallthrough? | **401** | M2M routes are not interactive; falling through to a sign-in page for a curl-using client is worse than a clear 401. |
| 2 | Session key shape | **`(jwt_idp_name, token-uuid)`** | Stable cache key; isolates different IdPs naturally. |
| 3 | `enrichKubernetesClaims` | **Remove entirely** | Pure ergonomics, real security cost (cross-issuer claim spoofing). PPL can match raw `claim/kubernetes.io.namespace`. |
| 4 | Session manager touching JWT sessions | **Skip** (existing `RefreshDisabled` + `OauthToken==nil` already handles this) | No refresh path makes sense for verify-only tokens. |
| 5 | Downstream identity propagation | **Pomerium-minted JWT only**, never pass through the source token | Upstreams should trust Pomerium's signature, not chase external JWKS. |
| 6 | Cookie session AND `Authorization: Bearer` on the same request | **400 Bad Request** | Mutually exclusive trust contexts; mixing them is a client bug or attempted confusion. |
| 7 | Precedence between `BearerTokenFormat` and `accept_jwt_idps` | **`accept_jwt_idps` wins** (and `BearerTokenFormat` becomes irrelevant on JWT-IdP routes) | Single source of truth for "this route accepts JWTs." |
| 8 | Per-IdP claim mapping | **None** | PPL already references raw claims directly; a mapping layer adds complexity without unlocking capability. |

## 6. Concrete diff (high-level)

### Proto changes — `pkg/grpc/config/config.proto`

```proto
// New message
message JwtIdentityProvider {
  string name           = 1;  // stable identifier, referenced by routes
  string issuer         = 2;  // `iss` claim must match
  string jwks_url       = 3;  // optional explicit JWKS URL
  repeated string supported_algs = 4;  // default: RS256, ES256, EdDSA
}

message Settings {
  // ... existing fields ...
  repeated JwtIdentityProvider jwt_identity_providers = 184;
}

// Per-route reference
message JwtIdpAcceptance {
  string name              = 1;  // matches jwt_identity_providers[].name
  repeated string audiences = 2; // MUST be non-empty
}

message Route {
  // ... existing fields ...
  repeated JwtIdpAcceptance accept_jwt_idps = 95;
}
```

### Removed proto fields

- `Settings.idp_identity_token_allowed_audiences` (field 182)
- `Settings.idp_jwks_url` (field 183)
- `Provider.identity_token_allowed_audiences` (field 11)
- `Provider.jwks_url` (field 12)
- `Route.idp_identity_token_allowed_audiences` (field 94)

Reserved-out, not reused (they exist briefly only in this branch; we delete
without a deprecation cycle since nothing released uses them).

### Go config changes

- `config.Options` gains `JWTIdentityProviders []JwtIdentityProvider`.
- `config.Policy` gains `AcceptJWTIdps []JwtIdpAcceptance`; loses
  `IDPIdentityTokenAllowedAudiences`.
- `config.Options` loses `IDPIdentityTokenAllowedAudiences` and `IDPJWKSURL`.
- A new resolver type, e.g.
  `config.JWTIdpResolver`, that owns one `*extjwt.Provider` per named entry
  and exposes `VerifyForRoute(ctx, policy, rawJWT) (claims, providerName, error)`.

### Code paths to change

- **`config/session.go`** — `IncomingIDPTokenSessionCreator` no longer
  consults `BearerTokenFormat` to dispatch by global IdP. Instead, it asks
  the route's `AcceptJWTIdps` for a verifier:
  1. `parseIssClaim(rawToken)` (header.payload split, no signature check yet).
  2. Find route's `AcceptJWTIdps` entry whose named provider has matching `issuer`.
  3. Verify via that provider.
  4. Audience check intersects token `aud` with that entry's `audiences`.
  5. Session ID = uuidv5(jwt_idp_name + token).

- **`authorize/check_response.go`** (or its session-loader sibling) — add the
  "bearer AND cookie ⇒ 400" gate.

- **`pkg/identity/providers.go`** — remove `extjwt.Name` from the registry;
  the resolver constructs `extjwt.Provider` instances directly.

- **`pkg/identity/oidc/extjwt/extjwt.go`** — drop the OAuth2-stub methods
  (`SignIn`, `Authenticate`, `Refresh`, `Revoke`, `UpdateUserInfo`, `SignOut`,
  `DeviceAuth`, `DeviceAccessToken`). The type no longer needs to satisfy
  `identity.Authenticator`. Keep `VerifyIdentityToken`,
  `audienceMatches`, and the lazy JWKS-fetcher core. Add the
  `supported_algs` allowlist plumbed through to `go_oidc.Config.SupportedSigningAlgs`
  (fixes [Review finding #5](#)).

- **`config/identity.go`** — the existing global `GetIdentityProviderForPolicy`
  is untouched (it still builds the browser IdP). The JWT-IdP resolver is a
  parallel mechanism, not a substitute.

### Code paths to remove

- `enrichKubernetesClaims` and its tests in `pkg/identity/oidc/extjwt/`.
- The `idp_provider: jwt` registry entry.
- The two POC integration tests' use of `claim/groups: "k8s:ns:..."` —
  rewrite to `claim/kubernetes.io.namespace: "platform"` instead.

## 7. Behavior table

| Request type | Has bearer? | Has cookie? | Route has `accept_jwt_idps`? | Outcome |
|---|---|---|---|---|
| Browser unauthenticated | no | no | no | 302 to SSO (unchanged) |
| Browser unauthenticated | no | no | yes | **401** (decision #1) |
| Browser authenticated | no | yes | any | PPL evaluation with cookie session (unchanged) |
| M2M with token | yes | no | no | **401** (decision #7) |
| M2M with token, matching IdP | yes | no | yes | Verify, create/find session, PPL evaluation |
| M2M with token, no matching IdP (issuer/audience mismatch) | yes | no | yes | 401 with logged reason |
| Mixed (suspicious) | yes | yes | any | **400 Bad Request** (decision #6) |

## 8. PPL — unchanged surface area

```yaml
# Match a specific SA
- allow:
    and:
      - claim/sub: "system:serviceaccount:platform:api-client"

# Match by namespace (uses Pomerium's flatten of nested claims)
- allow:
    and:
      - claim/kubernetes.io.namespace: "platform"

# Match either pod-uid or sa-name
- allow:
    or:
      - claim/kubernetes.io.pod.name: "trusted-pod"
      - claim/kubernetes.io.serviceaccount.name: ["api-client", "indexer"]
```

No new criteria, no new predicate types, no enrichment.

## 9. Tests

### Unit tests (`pkg/identity/oidc/extjwt/`)

Keep and adapt:
- Happy path
- Wrong audience
- Wrong issuer
- Expired / future-nbf
- Algorithm allowlist (NEW: assert ES256 with no allowlist is REJECTED;
  assert ES256 succeeds when `supported_algs: [ES256]` is set — fixes the
  RS256-default bug)
- Garbage token

Drop:
- `TestEnrichKubernetesClaims` and dependent groups-synthesis assertions.

### Integration tests (`authorize/jwt_bearer_int_test.go`)

Adapt:
- Replace `cfg.Options.Provider = "jwt"` and audience-on-options with the new
  `JWTIdentityProviders` + per-route `AcceptJWTIdps` shape.
- Replace `claim/groups: "k8s:ns:platform"` policies with
  `claim/kubernetes.io.namespace: "platform"`.

Add new cases:
- **Browser route stays working**: same Pomerium has one OIDC route and one
  JWT route — both work in the same process.
- **Multi-issuer route**: route lists two `accept_jwt_idps` entries, tokens
  from either issuer pass, tokens from neither are rejected.
- **400 on cookie+bearer collision**.
- **401 on JWT-only route with no Authorization header** (no fallthrough to
  SSO).
- **401 on token whose `iss` matches a known IdP but the route doesn't list
  that IdP**.

### K3s integration test (`authorize/jwt_bearer_k3s_int_test.go`)

Adapt to the new config shape. Otherwise identical assertions.

## 10. Migration

The POC is unreleased — no migration concerns. The change plan replaces the
POC wholesale on this branch before merge.

If we'd already released the POC (we haven't), the migration would be:

```yaml
# Before (POC, deprecated)
idp_provider: jwt
idp_provider_url: https://oidc.eks.<region>.amazonaws.com/id/ABC
idp_identity_token_allowed_audiences: [pomerium.api]
bearer_token_format: idp_identity_token
routes:
  - from: https://api.example.com
    policy: ...

# After (this plan)
idp_provider: oidc                 # actual browser IdP, or leave unset
idp_provider_url: ...
jwt_identity_providers:
  - name: eks-prod
    issuer: https://oidc.eks.<region>.amazonaws.com/id/ABC
routes:
  - from: https://api.example.com
    accept_jwt_idps:
      - name: eks-prod
        audiences: [pomerium.api]
    policy: ...
```

## 11. Open questions / out of scope

- **TokenReview integration** — deferred. Will likely become an optional flag
  on a `JwtIdentityProvider` entry (`token_review: true` + a Kubernetes
  kubeconfig reference) but is not part of this change.
- **Per-route signing algorithm tightening** — not in v1; the IdP-level
  `supported_algs` applies to all routes referencing that IdP.
- **Multi-cluster federation with reviewer JWTs** — deferred; not blocking
  the basic JWT-verify flow.
- **Caching JWKS across config reloads** — handled by `go-oidc`'s
  `RemoteKeySet`; reviewed in the review pass. The btree leak in
  `authenticate/identity.go` is a pre-existing pattern issue and is not
  resolved by this plan (it tracks browser-IdP authenticators, not JWT
  ones). Track separately.
- **Audit-log shape** — JWT-authenticated requests should log
  `jwt_idp: <name>` so operators can attribute access by trust root.
  Design TBD; trivial.

## 12. Estimated size

| Change | Approximate size |
|---|---|
| Proto edits + regen | ~200 lines (mostly generated) |
| `JWTIdpResolver` + named-provider lookup | ~150 lines |
| `config.Options`/`Policy` field plumbing | ~100 lines |
| `extjwt` slimming (drop OAuth2 stubs, add alg allowlist, remove enrichment) | -120 / +30 net |
| `IncomingIDPTokenSessionCreator` refactor for per-route dispatch | ~80 lines |
| Cookie-and-bearer collision gate | ~20 lines |
| Tests (adapt + add new cases) | ~300 lines |
| Removal of POC config knobs | ~-100 lines |
| **Net** | **~+650 lines** (vs POC's +600) |

A bit larger than the POC, but the resulting model is the one we want to ship.
