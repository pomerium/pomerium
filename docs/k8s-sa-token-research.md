# Accepting Kubernetes Service Account Tokens as a Pomerium Identity

**Status:** Research / design exploration
**Author:** Denis Mishin (`dmishin@pomerium.com`)
**Date:** 2026-05-25
**Branch:** `wasaga/poc-accept-k8s-token`

---

## 1. Executive summary

Pomerium already supports an "external IdP access/identity token in the
`Authorization: Bearer …` header" flow (originally added for Microsoft Entra /
Azure service-principal tokens). That mechanism is general — anything Pomerium's
`identity.Authenticator` interface can verify can be used as an inbound bearer
credential.

**Question:** can we extend this so that a pod running in the same Kubernetes
cluster as Pomerium can present its projected ServiceAccount token in
`Authorization: Bearer …` and have Pomerium treat it as a verifiable, in-cluster
identity?

**Short answer:** yes, this is sound, well-precedented (Vault, Istio,
oauth2-proxy, Kubernetes Dashboard, Linkerd-identity, kube-oidc-proxy), and
works the same way on all three major managed Kubernetes platforms (GKE, EKS,
AKS). It maps cleanly onto Pomerium's existing `VerifyIdentityToken` /
`VerifyAccessToken` plumbing in
[`pkg/identity/oidc/oidc.go`](../pkg/identity/oidc/oidc.go) and
[`config/session.go`](../config/session.go).

There are two distinct verification paths — OIDC/JWKS or `TokenReview` API —
with a real and measurable trade-off (latency vs. revocation latency). The
recommended shape is "JWKS by default, `TokenReview` opt-in," mirroring
HashiCorp Vault's two parallel auth methods.

The single non-negotiable design constraint is **audience binding**: a pod's
default API-server ServiceAccount token must **not** be accepted as a valid
Pomerium credential, because that would mean every pod with a default
`automountServiceAccountToken: true` is implicitly authenticated to Pomerium.
Operators must mint a Pomerium-specific token through a `projected` volume.

---

## 2. Background: how Pomerium handles inbound bearer tokens today

The existing flow:

| Component | File |
|---|---|
| Header extraction (`Authorization: Bearer <token>`) | [`config/session.go:447–487`](../config/session.go) |
| `IncomingIDPTokenSessionCreator` | [`config/session.go:108–322`](../config/session.go) |
| HTTP endpoints on `authenticate` service | [`authenticate/handlers_verify.go`](../authenticate/handlers_verify.go) |
| `identity.Authenticator` interface | [`pkg/identity/providers.go:42–43`](../pkg/identity/providers.go) |
| OIDC reference implementation | [`pkg/identity/oidc/oidc.go:429–474`](../pkg/identity/oidc/oidc.go) |

Two policy/global settings control behavior:

- `bearer_token_format` = `BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN` →
  `VerifyAccessToken` (today: calls the IdP's `userinfo` endpoint with the token)
- `bearer_token_format` = `BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN` →
  `VerifyIdentityToken` (today: OIDC ID-token verification — fetch
  `/.well-known/openid-configuration`, fetch JWKS, verify JWT signature, check
  `iss`/`aud`/`exp`)

A Kubernetes ServiceAccount token **is** a JWT signed by the cluster, with
`iss`, `sub`, `aud`, `exp`, `iat`, `nbf` claims — i.e., it slots naturally into
the **`VerifyIdentityToken` path** if we configure an OIDC identity provider
whose issuer URL is the cluster's `--service-account-issuer`. So at first
approximation, "Pomerium supports K8s SA tokens" reduces to "operator configures
the cluster's OIDC issuer as a Pomerium IdP, mints projected tokens with the
right audience, and turns on `bearer_token_format: idp_identity_token`."

The interesting question is whether (and where) we want to deviate from that
plain OIDC path.

---

## 3. Kubernetes ServiceAccount token primer

### 3.1 Legacy secret-backed tokens vs projected (bound) tokens

Historically, every ServiceAccount got an auto-generated
`kubernetes.io/service-account-token` Secret. Those tokens had **no `exp`
claim**, were not bound to any pod, and lived as long as the Secret — long-lived
bearer credentials.

Replacement timeline:

| K8s version | Change |
|---|---|
| 1.20 alpha → 1.21 beta → **1.22 stable** | `BoundServiceAccountTokenVolume` — kubelet stops using Secret-mounted tokens, requests fresh tokens from `TokenRequest`, mounts via `projected` volume |
| 1.24 | Auto-creation of the legacy Secret stopped (`LegacyServiceAccountTokenNoAutoGeneration`); `LegacyServiceAccountTokenCleaner` reaps unused ones |
| 1.29 → **1.32 stable** | KEP-4193 adds `jti` claim (`ServiceAccountTokenJTI`) and `kubernetes.io.node.{name,uid}` claim (`ServiceAccountTokenPodNodeInfo`) |
| 1.29 alpha → 1.31 beta → **1.33 stable** | KEP-4193 `ServiceAccountTokenNodeBinding` — tokens bound to a Node object |

A `projected` SA-token volume looks like:

```yaml
volumes:
- name: pomerium-token
  projected:
    sources:
    - serviceAccountToken:
        path: token
        audience: pomerium.example.com   # MUST be a Pomerium-specific audience
        expirationSeconds: 3600           # 600–86400, kubelet rotates at ~80% TTL
```

Key invariants:

- **Bounded lifetime**: default 1 h, min 10 min, max 24 h. Kubelet rotates the
  file on-disk when ~80% of TTL elapses.
- **Bound to a pod**: JWT carries `kubernetes.io.pod.{name,uid}`. The API
  server invalidates a token 60 s past its bound pod's `deletionTimestamp`.
- **Audience-restricted**: caller declares the intended recipient when
  requesting; `aud` is a JSON array.
- Issued via the `TokenRequest` API
  (`POST /api/v1/namespaces/<ns>/serviceaccounts/<name>/token`).

### 3.2 Claims in a projected token

```json
{
  "aud": ["pomerium.example.com"],
  "exp": 1729605240,
  "iat": 1729601640,
  "nbf": 1729601640,
  "iss": "https://oidc.eks.us-west-2.amazonaws.com/id/ABC123",
  "jti": "aed34954-b33a-4142-b1ec-389d6bbb4936",
  "sub": "system:serviceaccount:my-namespace:my-serviceaccount",
  "kubernetes.io": {
    "namespace": "my-namespace",
    "serviceaccount": { "name": "my-serviceaccount", "uid": "14ee3fa4-…" },
    "pod":            { "name": "my-pod",            "uid": "5e0bd49b-…" },
    "node":           { "name": "my-node",           "uid": "646e7c5e-…" }
  }
}
```

Stability:

| Claim | Stable since |
|---|---|
| `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `kubernetes.io.namespace`, `kubernetes.io.serviceaccount.{name,uid}`, `kubernetes.io.pod.{name,uid}` | 1.22 |
| `jti` | 1.32 |
| `kubernetes.io.node.{name,uid}` | 1.32 (only when bound object is a Pod) |
| Node-bound tokens (`ServiceAccountTokenNodeBinding`) | 1.33 |

**Important:** there is no `email`, `name`, `preferred_username`, or `groups`.
The identity is `sub = system:serviceaccount:<ns>:<sa>` plus the structured
`kubernetes.io` block. Pomerium must synthesize any "human-friendly" claims.

---

## 4. Two verification paths

### 4.1 Path A — OIDC / JWKS (`Service Account Issuer Discovery`, KEP-1393)

Made stable in K8s 1.21. The API server itself acts as an OIDC-discovery-
compatible IdP for its SA tokens:

- `--service-account-issuer=<URL>` sets `iss` and the `issuer` field in the
  discovery document
- `--service-account-jwks-uri=<URL>` overrides the advertised `jwks_uri`
- `/.well-known/openid-configuration` — discovery document
- `/openid/v1/jwks` — signing keys

By default these endpoints are **not anonymous**: a built-in ClusterRole
`system:service-account-issuer-discovery` (`get` on the two URLs) must be bound
to either `system:anonymous` or to `system:serviceaccounts` (or a specific SA).
In the cloud-managed cases below, the cloud provider exposes the JWKS on a
separate public CDN-style URL outside the apiserver, so this RBAC dance is
sidestepped.

Verification is plain OIDC: cache the JWKS, verify signature, then check `iss`,
`aud`, `exp`, `nbf`. Slots directly into Pomerium's existing
[`pkg/identity/oidc/oidc.go`](../pkg/identity/oidc/oidc.go) verifier.

### 4.2 Path B — TokenReview API (`authentication.k8s.io/v1`)

The verifier POSTs the bearer token to the apiserver:

```json
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "spec": {
    "token": "<bearer token from Authorization header>",
    "audiences": ["pomerium.example.com"]
  }
}
```

Response (success):

```json
{
  "status": {
    "authenticated": true,
    "user": {
      "username": "system:serviceaccount:my-namespace:my-serviceaccount",
      "uid": "14ee3fa4-…",
      "groups": [
        "system:serviceaccounts",
        "system:serviceaccounts:my-namespace",
        "system:authenticated"
      ],
      "extra": {
        "authentication.kubernetes.io/pod-name": ["my-pod"],
        "authentication.kubernetes.io/pod-uid":  ["5e0bd49b-…"],
        "authentication.kubernetes.io/node-name":["my-node"],
        "authentication.kubernetes.io/node-uid": ["646e7c5e-…"]
      }
    },
    "audiences": ["pomerium.example.com"]
  }
}
```

Required RBAC: the verifier's own SA needs the built-in
`system:auth-delegator` ClusterRole (which grants `create` on
`tokenreviews.authentication.k8s.io` and on
`subjectaccessreviews.authorization.k8s.io`).

**Audience semantics:** the apiserver returns `authenticated: true` iff
`spec.audiences ∩ token.aud ≠ ∅`. The response echoes the intersection in
`status.audiences`; a properly-coded client must verify the echoed audience is
what it expects (older non-audience-aware authenticators return an empty
`status.audiences`, which means "valid only against the apiserver itself" —
that's the foot-gun audience-confusion case).

**Pod-binding enforcement (the killer feature):** the apiserver's in-tree
authenticator does the etcd lookup. If `kubernetes.io.pod.uid` doesn't match a
live Pod (deleted, recreated with a new UID, or >60 s past `deletionTimestamp`),
TokenReview returns `authenticated: false`, **even if the JWT is
cryptographically valid and `exp` is in the future**. This is the single
biggest reason to consider TokenReview.

### 4.3 Comparison

| Property | OIDC/JWKS | TokenReview |
|---|---|---|
| Per-request latency | ~0 (local crypto after one cached JWKS fetch) | apiserver RTT, subject to APF |
| Availability dependency | JWKS fetch only (cacheable) | Hard dependency on apiserver |
| RBAC required | `get` on discovery URLs (often pre-bound) | `system:auth-delegator` (broad!) |
| `aud` enforcement | Verifier checks itself | API server enforces intersection |
| Signature trust | JWKS public keys | Implicit (apiserver is the verifier) |
| **Pod-UID revocation on pod-delete** | **Not enforced** — JWT valid until `exp` | **Enforced** within ~60 s |
| Key-rotation handling | Verifier refreshes JWKS on `kid` miss | Transparent |
| Works for tokens from other clusters | Yes (federation) | No (per-cluster reviewer JWTs) |
| Works air-gapped from apiserver | Yes | No |
| Rate-limit exposure | None | Real ([k/k #71811](https://github.com/kubernetes/kubernetes/issues/71811)) |

**Mitigation if JWKS-only:** short `expirationSeconds` (≤ 600 s), strict `aud`,
treat tokens past kubelet's natural rotation point with suspicion. Even so,
revocation is bounded by `exp`, not by pod lifecycle.

---

## 5. Cloud provider support

### 5.1 Google GKE

- **Issuer URL:** `https://container.googleapis.com/v1/projects/<PROJECT>/locations/<LOCATION>/clusters/<CLUSTER>`
- **JWKS:** publicly fetchable at `.../clusters/<CLUSTER>/jwks` and discovery at
  `.../clusters/<CLUSTER>/.well-known/openid-configuration` — anonymous access
  is the entire point of GKE Workload Identity Federation
- **Default in-cluster token's `iss`:** the same public URL above; this holds
  for both the default auto-mounted token and any projected token with a custom
  audience — only `aud` differs
- **Autopilot:** Workload Identity is mandatory; projected-token volumes still
  work; the OIDC endpoint is still public
- **Private clusters:** the OIDC endpoint sits at `container.googleapis.com`,
  which is a Google-managed control-plane service, not in your VPC — still
  reachable

References:
[About Workload Identity Federation for GKE](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity),
[Configure Workload Identity Federation with Kubernetes](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-kubernetes).

### 5.2 AWS EKS

- **Issuer URL:** `https://oidc.eks.<region>.amazonaws.com/id/<id>`
- **JWKS:** publicly fetchable at `.../keys` (and discovery at
  `.../.well-known/openid-configuration`); responses are throttled and have
  `Cache-Control` headers
- **Signing-key rotation:** every ~7 days — the verifier must handle
  `kid`-miss re-fetch promptly
- **Default in-cluster token's `iss`:** the same public URL above for every
  projected token; only `aud` differs between (default) and (IRSA-style
  `sts.amazonaws.com` audience)
- **Pod Identity (the newer alternative to IRSA):** does *not* use the cluster
  OIDC issuer at all (uses an EKS-managed agent and the
  `pods.eks.amazonaws.com` service principal) — irrelevant to JWT verification
- **VPC-isolated apiserver:** the OIDC URL is still public; ensure DNS for
  `oidc.eks.<region>.amazonaws.com` resolves via public DNS (operators on VPC
  endpoints commonly add a Route 53 conditional resolver)

References:
[IAM Roles for Service Accounts technical overview](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts-technical-overview.html),
[Fetch signing keys to validate OIDC tokens](https://docs.aws.amazon.com/eks/latest/userguide/irsa-fetch-keys.html),
[amazon-eks-pod-identity-webhook](https://github.com/aws/amazon-eks-pod-identity-webhook).

### 5.3 Azure AKS

- **Issuer URL** (when enabled): `https://<region>.oic.prod-aks.azure.com/<tenant-guid>/<cluster-guid>/`
- **JWKS:** publicly fetchable at `.../openid/v1/jwks` and discovery at
  `.../.well-known/openid-configuration`
- **Must be explicitly enabled** with `--enable-oidc-issuer`. New clusters on
  K8s 1.34+ enable it by default; older or pre-existing clusters do not.
  Enabling on an existing cluster restarts the apiserver, and once enabled
  cannot be disabled.
- **Default in-cluster token's `iss`** when issuer is enabled: that same public
  URL. Without `--enable-oidc-issuer`, the apiserver uses a non-public issuer
  (`https://kubernetes.default.svc.cluster.local`) and there is no externally-
  reachable JWKS — verification then requires TokenReview, not OIDC.
- **Signing-key rotation:** old and new keys are both valid for 24 h after
  rotation.

References:
[Create an OIDC Provider for your AKS cluster](https://learn.microsoft.com/en-us/azure/aks/use-oidc-issuer),
[Use a Microsoft Entra Workload ID on AKS](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview).

### 5.3a K3s (and RKE2, k3d)

K3s is a single Go binary that **vendors upstream `kube-apiserver`** and
launches it in-process with an args-map assembled by K3s's wrapper code
([`pkg/daemons/control/server.go`](https://github.com/k3s-io/k3s/blob/master/pkg/daemons/control/server.go)).
Anything that works on vanilla `kube-apiserver` (TokenReview, OIDC discovery,
projected SA tokens) works identically on K3s — only defaults and file layout
differ.

- **Default issuer:** `https://kubernetes.default.svc.<cluster-domain>` (with
  `--cluster-domain=cluster.local` by default, so
  `https://kubernetes.default.svc.cluster.local`). `api-audiences` defaults to
  `<issuer>,k3s`. Pre-1.20 K3s emitted the literal string `"k3s"` as the
  issuer; tokens from those old clusters cannot be OIDC-discovered and require
  TokenReview.
- **Override on K3s:** any upstream apiserver flag is passable via
  `--kube-apiserver-arg`, e.g. in `/etc/rancher/k3s/config.yaml`:
  ```yaml
  kube-apiserver-arg:
    - "service-account-issuer=https://k3s.example.com"
    - "service-account-jwks-uri=https://k3s.example.com/openid/v1/jwks"
  ```
  See [docs.k3s.io/cli/server](https://docs.k3s.io/cli/server) and the SUSE KB
  ["How to Update or Add Arguments to the kube-apiserver in RKE2 and K3s Clusters"](https://support.scc.suse.com/s/kb/How-to-Update-or-Add-Arguments-to-the-kube-apiserver-in-RKE2-and-K3s-Clusters).
- **OIDC discovery endpoints** are the same upstream paths and require the
  `system:service-account-issuer-discovery` ClusterRole binding for anonymous
  access (just like vanilla K8s); K3s does not pre-bind to `system:anonymous`.
- **Signing keys** live at
  `/var/lib/rancher/k3s/server/tls/service.current.key` (signing) and
  `service.key` (verification bundle — concatenated PEM blocks, supports old
  keys for rotation). K3s **does not auto-rotate** the signing key;
  `k3s certificate rotate-ca` is the manual ceremony. See
  [docs.k3s.io/cli/certificate](https://docs.k3s.io/cli/certificate).
- **Service CIDR is `10.43.0.0/16` by default** (not the kubeadm
  `10.96.0.0/12`). The in-cluster `kubernetes` Service is `10.43.0.1`. Matters
  for hard-coded network policies and trust zones, not for verification logic.
- **Datastore:** kine-on-SQLite (single-node) or embedded etcd (HA) — does not
  affect TokenReview hot-path latency in any measurable way.
- **Default-issuer URL is not externally routable.** This is the most
  practical gotcha for K3s: `kubernetes.default.svc.cluster.local` resolves
  only inside the cluster. An external Pomerium verifying via JWKS must either
  override the issuer at install time to a reachable hostname, or fetch JWKS
  from the apiserver's external address while still trusting the in-cluster
  issuer string. Cloud-managed K8s providers solve this by exposing a public
  CDN-style JWKS URL; K3s operators must do it themselves.
- **k3d** ([k3d.io](https://k3d.io)) wraps K3s in Docker containers and
  inherits 100% of this behavior. Override the issuer at cluster-create with
  `--k3s-arg "--kube-apiserver-arg=service-account-issuer=https://..."` if
  external verification is needed
  ([k3d-io/k3d#1187](https://github.com/k3d-io/k3d/issues/1187)).
- **RKE2** ([docs.rke2.io](https://docs.rke2.io)) shares the same
  Rancher/SUSE configuration ergonomics (`/etc/rancher/rke2/config.yaml`,
  `--kube-apiserver-arg`) but runs the control plane as **static pods** rather
  than in-process — closer to vanilla `kubeadm` than K3s is. The override
  syntax and default-issuer construction are identical to K3s; keys live
  under `/var/lib/rancher/rke2/server/tls/`.

K3s sources/references:
[`pkg/daemons/control/server.go`](https://github.com/k3s-io/k3s/blob/master/pkg/daemons/control/server.go),
[docs.k3s.io/architecture](https://docs.k3s.io/architecture),
[docs.k3s.io/cli/server](https://docs.k3s.io/cli/server),
[docs.k3s.io/cli/certificate](https://docs.k3s.io/cli/certificate),
[docs.k3s.io/installation/configuration](https://docs.k3s.io/installation/configuration),
[k3s-io/k3s#10573](https://github.com/k3s-io/k3s/issues/10573),
[k3s-io/k3s discussions/4173](https://github.com/k3s-io/k3s/discussions/4173).

### 5.4 Reaching the apiserver as a fallback

The `TokenReview` path works identically on all three platforms (and on
vanilla K8s) — `https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews`
from any in-cluster pod, using its own SA token, with
`system:auth-delegator` RBAC.

The apiserver also serves the OIDC discovery document and JWKS internally at
`/.well-known/openid-configuration` and `/openid/v1/jwks`. For private clusters
or AKS without OIDC issuer enabled, Pomerium can point its `jwks_uri` at
`https://kubernetes.default.svc/openid/v1/jwks` and authenticate the fetch with
its own SA token. This is a useful fallback that should be documented.

### 5.5 Workload Identity features — related but distinct (DON'T REUSE AUDIENCES)

All three providers have a feature that exchanges a projected SA token for a
cloud-provider access token. Pomerium does not participate in this exchange —
but operators will be tempted to reuse the projected token already mounted on
their pods. **They must not.** The audiences in flight are:

| Platform | Projected `aud` for cloud exchange |
|---|---|
| GKE Workload Identity | `<PROJECT_ID>.svc.id.goog` |
| EKS IRSA | `sts.amazonaws.com` |
| AKS Workload Identity | `api://AzureADTokenExchange` |
| (Default API-server audience) | `https://kubernetes.default.svc.cluster.local` |

Accepting any of those audiences in Pomerium would mean any workload that has
Workload Identity (or just a default SA-token mount) is silently authenticated
to Pomerium. Operators must declare a Pomerium-specific audience
(e.g. `pomerium.<cluster-domain>`) and project a separate token with that
audience via a `serviceAccountToken` source. Multiple projected sources can
coexist on the same pod.

### 5.6 Default token lifetimes

| Path | Default `expirationSeconds` |
|---|---|
| Auto-mounted `kube-api-access-*` projected token | 3600 (1 h), kubelet rotates at ~80% TTL |
| EKS IRSA webhook | 86400 (24 h), configurable via SA annotation |
| AKS Workload Identity | 3600 (1 h), configurable 3600–86400 via `azure.workload.identity/service-account-token-expiration` annotation |

For Pomerium, a 1–2 h lifetime with kubelet rotation is the right operating
point — short enough to bound replay, long enough to amortize JWKS verification.

---

## 6. Prior art

### 6.1 HashiCorp Vault — the canonical "two parallel paths" implementation

Vault ships *both* mechanisms as separate auth methods. Studying this split is
the single most useful exercise before implementing the same thing in Pomerium.

- [**`kubernetes` auth method**](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
  — calls `TokenReview`. Configuration: `kubernetes_host`, `kubernetes_ca_cert`,
  `token_reviewer_jwt`, `disable_local_ca_jwt`. On Vault 1.9+,
  `disable_iss_validation` defaults to `true` because the apiserver
  authoritatively checks `iss` itself. Roles bind to
  `bound_service_account_names`, `bound_service_account_namespaces`, and
  `audience`. The `use_annotations_as_alias_metadata` flag pulls **annotations
  off the SA object** so Vault policies can template against them — this is how
  Vault solves the "SA tokens have no `email`/`groups`" problem.
- [**`jwt` auth method** with Kubernetes as an OIDC provider](https://developer.hashicorp.com/vault/docs/auth/jwt/oidc-providers/kubernetes)
  — pure JWKS validation against the cluster's discovery URL. No
  `TokenReview` round-trip, no reviewer JWT, no apiserver dependency on the hot
  path — but no revocation either: tokens stay valid until `exp` regardless of
  pod lifecycle.

Vault explicitly documents the trade-off. That trade-off is the whole design
question for Pomerium.

### 6.2 Istio

Istio splits its concerns into
[`PeerAuthentication`](https://istio.io/latest/docs/concepts/security/) (mTLS at
L4) and
[`RequestAuthentication`](https://istio.io/latest/docs/reference/config/security/request_authentication/)
(JWT at L7). `RequestAuthentication` is a generic JWT validator with `jwksUri` /
inline `jwks`, mandatory `issuer`, optional `audiences`. Pointing it at the
cluster's OIDC issuer works, but Istio is not k8s-SA-aware — the identity
extracted goes into `AuthorizationPolicy` rules as opaque strings. The pattern
is identical to what Pomerium would build.

### 6.3 oauth2-proxy

[`oauth2-proxy`](https://github.com/oauth2-proxy/oauth2-proxy) supports SA
tokens via `--skip-jwt-bearer-tokens` and
`--extra-jwt-issuers=<issuer>=<audience>`. Pure JWKS validation through OIDC
discovery; no `TokenReview` path. It's the closest analog to what Pomerium is
contemplating and the simplest model to copy if we want JWKS-only.

### 6.4 Linkerd, Knative, SPIFFE/SPIRE

[Linkerd](https://linkerd.io/2021/12/28/using-kubernetess-new-bound-service-account-tokens-for-secure-workload-identity/)
uses a projected SA token (24 h TTL) as the *seed* for a CSR exchange with the
`linkerd-identity` controller, which returns an x.509 cert with a SPIFFE ID
`spiffe://<cluster>/ns/<ns>/sa/<sa>`. The SA token is never the long-lived
bearer at the edge — it's an input to a cert-bootstrap step. Worth flagging
because the "right" answer for inside-the-cluster identity is arguably mTLS, not
bearer JWTs; the case for bearer SA tokens in Pomerium is mainly **zero-code
client integration** (any HTTP library that sets `Authorization: Bearer`
works) and ingress traffic that originates inside the cluster but terminates at
Pomerium.

### 6.5 kube-oidc-proxy and Kubernetes Dashboard

[`jetstack/kube-oidc-proxy`](https://github.com/jetstack/kube-oidc-proxy)
(archived 2024, Tremolo-maintained fork active) does the *opposite* of what
Pomerium would do — accepts OIDC user tokens and proxies them to the apiserver
with impersonation headers. Relevant feature: it falls back to `TokenReview`
for bearer tokens that fail OIDC verification, so SA tokens still work through
the proxy. This **dual-path design** (try OIDC first, fall back to
TokenReview) is a reasonable shape for Pomerium.

The **Kubernetes Dashboard** accepts `Authorization: Bearer <sa-token>` and
submits it to the apiserver to derive identity — UI-layer `TokenReview`. The
widely-reported Tesla cryptojacking incident, where a publicly-exposed Dashboard
gave attackers cluster control, is the cautionary tale: "bearer token =
identity" is only safe if the operator commits to the discipline.

### 6.6 Tools that *don't* validate inbound SA tokens

For completeness: ArgoCD, Crossplane, External Secrets Operator use SA tokens
in the *other* direction (as outbound credentials to talk to a cluster's
apiserver). They are not relevant prior art for this design.

---

## 7. Security considerations

### 7.1 Replay inside the cluster

A SA token is a bearer token. Any process that can `cat
/var/run/secrets/.../token` can impersonate the SA. Mitigations stack:

1. Short `expirationSeconds` (≤ 1 h).
2. **Pod-bound tokens** — the apiserver embeds `kubernetes.io.pod.{name,uid}`
   and refuses `TokenReview` for tokens whose bound object no longer exists.
   This is genuinely only enforceable via TokenReview; JWKS validation accepts
   the token regardless.
3. `aud` restriction so the token can *only* be presented to Pomerium.

### 7.2 Audience confusion — the one non-negotiable

The default projected-token audience is
`https://kubernetes.default.svc.cluster.local`. If Pomerium accepted that
audience, every workload's default SA token would simultaneously be a valid
Pomerium credential *and* a valid apiserver credential. A compromise of one is
a compromise of both, and an SSRF in any upstream behind Pomerium could pivot
to the apiserver.

**Pomerium must require operators to mount a dedicated audience and must refuse
to start if a route is configured with the apiserver's default audience or any
of the cloud-provider Workload Identity audiences.**

### 7.3 Bearer leakage in logs

`Authorization` header values must be on a strict denylist for request logging
and access-log custom fields. The risk is higher with SA tokens than with OIDC
ID tokens because SA tokens are long-lived enough to be useful if pulled from a
log a day later (1 h TTL standard, 24 h legacy default).

### 7.4 Revocation latency — the central trade-off

| | JWKS validation | TokenReview |
|---|---|---|
| Hot-path latency | ~0 | apiserver RTT |
| Revocation on pod delete | None until `exp` | Immediate (within ~60 s) |
| Apiserver dependency | Bootstrap only | Per-request |
| Multi-cluster | Native | Per-cluster reviewer JWTs |

Recommended default: **JWKS, with TokenReview opt-in per route**. Document
that pod-bound revocation requires the opt-in.

### 7.5 SSRF via JWKS URL

If the operator can configure a `jwks_uri` (directly or via an issuer that
Pomerium discovers), an attacker who can influence that config can point
Pomerium at internal services or the cloud metadata endpoint. Recent
examples include the
[Keycloak `jwks_uri` SSRF issue](https://github.com/keycloak/keycloak/issues/45645)
and the
[Sigstore Fulcio MetaIssuer SSRF advisory](https://github.com/sigstore/fulcio/security/advisories/GHSA-59jp-pj84-45mr).

Mitigations: require `https://`, allowlist hostnames per route, refuse
`169.254.169.254` and RFC1918 by default — but with an explicit
`allow_private_jwks` knob because in-cluster apiservers do live on private IPs
and this is exactly the fallback scenario for AKS-without-issuer / private
clusters.

### 7.6 JWT algorithm pinning

Reject `alg: none`. Pin to `RS256`/`ES256`/`PS256`; refuse `HS*` on routes that
expect asymmetric signing — see
[JWT algorithm confusion attacks](https://portswigger.net/web-security/jwt/algorithm-confusion).
Modern Go JWT libraries (`go-jose`, `lestrrat-go/jwx`) require explicit `alg`
allowlists. Pomerium's config should require one and not infer from the JWKS.

### 7.7 RBAC blast-radius of `system:auth-delegator`

If TokenReview is enabled, Pomerium's SA holds `system:auth-delegator` and can
validate **any** token in the cluster. A Pomerium compromise becomes an
apiserver oracle (attacker can probe arbitrary tokens). Mitigations:

- Prefer JWKS for the default path.
- If TokenReview is enabled, put Pomerium in its own namespace with a
  NetworkPolicy that only allows egress to the apiserver Endpoints.
- The `system:service-account-issuer-discovery` ClusterRole is the lower-
  blast-radius alternative for the JWKS-fetch path.

---

## 7a. FAQ: operator-facing semantics

### Is the `audience` field basically "this token is for Pomerium"?

Yes. `aud` is the OAuth2/JWT convention for "intended recipient." When the
operator writes:

```yaml
serviceAccountToken:
  audience: pomerium.example.com
  expirationSeconds: 3600
  path: token
```

…the kubelet calls `TokenRequest` and the apiserver mints a JWT with
`"aud": ["pomerium.example.com"]`. Pomerium, configured with
`required_audiences: ["pomerium.example.com"]`, verifies the signature
(against the cluster's JWKS) and then requires that string to appear in `aud`.

A token minted for `sts.amazonaws.com` (IRSA) is **not** accepted by Pomerium,
and a token minted for Pomerium is **not** accepted by AWS STS. The cluster
signed both — only the audience differs. That's what prevents the
confused-deputy / audience-confusion attack.

### Can a pod have multiple ServiceAccounts mounted?

**No** — a pod has exactly one ServiceAccount, declared in
`pod.spec.serviceAccountName` (default: `default`). That's a hard Kubernetes
constraint; you cannot mount two different SA identities into the same pod.

**But** a pod can have **multiple projected tokens from the same SA, each with
a different audience**, by declaring multiple `serviceAccountToken` sources:

```yaml
spec:
  serviceAccountName: checkout
  volumes:
  - name: pomerium-token
    projected:
      sources:
      - serviceAccountToken:
          audience: pomerium.example.com
          expirationSeconds: 3600
          path: token
  - name: aws-token
    projected:
      sources:
      - serviceAccountToken:
          audience: sts.amazonaws.com
          expirationSeconds: 86400
          path: token
  containers:
  - name: app
    volumeMounts:
    - { name: pomerium-token, mountPath: /var/run/secrets/pomerium }
    - { name: aws-token,      mountPath: /var/run/secrets/aws }
```

This is exactly how IRSA, AKS Workload Identity, and the default
`/var/run/secrets/kubernetes.io/serviceaccount/token` mount already coexist on
a single pod — three projected tokens, same SA, three audiences. So a pod
calling AWS *and* talking through Pomerium *and* talking to kube-apiserver
needs three projected sources. The identity
(`system:serviceaccount:checkout:platform`) is the same in all three tokens;
the *recipient scope* differs.

If a pod genuinely needs **two distinct identities** (e.g. impersonating
different principals on different code paths), the answer is to split it into
two pods, each with its own SA. In practice this is rare — the SA represents
*what the pod is*, not *what it's allowed to do*; the latter is handled by
RBAC plus the set of audiences the SA is permitted to mint.

### Can I just reuse the auto-mounted default SA token?

You can, but you absolutely should not. The default token has
`aud = https://kubernetes.default.svc.cluster.local` (the apiserver's
audience). Accepting that audience in Pomerium would mean every pod in the
cluster with `automountServiceAccountToken: true` is implicitly authenticated
to Pomerium *and* simultaneously holds a credential for the apiserver.
Pomerium should refuse this audience at config-load time.

---

## 8. Mapping SA identity to a Pomerium user, and what PPL looks like

The natural unique ID is `sub: system:serviceaccount:<ns>:<name>`. `TokenReview`
returns it as `user.username`. Pomerium policy can pin on `sub` exactly — but
pitfalls:

1. **The `system:` prefix means naive code that treats `sub` as an email will
   break.** Pomerium's session/JWT mint logic must keep `sub` opaque and **not**
   populate `email` from it. Skim
   [`config/session.go:355–369`](../config/session.go) — `fillUserFromIDPClaims`
   reads `email` from claims, but a k8s SA token has no `email`, so a default
   user record would have an empty email. Make sure downstream code (audit
   logs, dashboards) doesn't choke on that.
2. **No `email`, `name`, `groups`, `preferred_username`.**
   - Vault's annotation-mirroring pattern is the right answer: an annotation
     like `pomerium.io/groups: platform,readonly` on the SA object becomes
     `groups` in the Pomerium session. This requires Pomerium to fetch the SA
     object (a `get serviceaccounts` permission) at validation time, or cache
     it via a watch.
   - Namespace as a synthetic group (`k8s:ns:<namespace>`) is a sensible
     default and lets policies grant by namespace without operator effort.
   - Cluster name (where Pomerium knows it) should be exposed as a claim;
     multi-cluster policies need it.
3. **PPL ergonomics.** Pomerium PPL should grow first-class predicates:
   `claim/kubernetes.io/namespace == "platform"`,
   `claim/sub starts_with "system:serviceaccount:platform:"`. The
   `starts_with` predicate matters because operators *will* otherwise try to
   write `email == "system:serviceaccount:…"` and be confused when it fails.
4. **`sub` colon parsing.** Pre-compute `k8s.namespace` and
   `k8s.serviceaccount` claims from the structured
   `kubernetes.io.serviceaccount.{name,namespace}` rather than parsing `sub`.

### Example PPL policies

After signature verification, every claim in the JWT was placed there by the
apiserver — the pod cannot forge them — so `sub` and `kubernetes.io.*` are
trustworthy. Sample policies:

```yaml
# Exact match on sub (works, but stringy and brittle)
- allow:
    and:
      - claim/sub: "system:serviceaccount:platform:checkout"

# Better — use the structured claims
- allow:
    and:
      - claim/kubernetes.io/namespace: "platform"
      - claim/kubernetes.io/serviceaccount/name: "checkout"

# Namespace-as-group (recommended default; Pomerium synthesizes this)
- allow:
    and:
      - groups/has: "k8s:ns:platform"

# Prefix match for "anything in the platform namespace"
- allow:
    and:
      - claim/sub:
          starts_with: "system:serviceaccount:platform:"

# Multi-cluster — require both a cluster claim and a namespace
- allow:
    and:
      - claim/k8s.cluster: "prod-us-east"
      - groups/has: "k8s:ns:checkout"
```

Practical recommendation: Pomerium synthesizes a small set of derived claims
at session-creation time so policies stay clean:

| Synthetic claim | Derived from |
|---|---|
| `k8s.namespace` | `kubernetes.io.namespace` |
| `k8s.serviceaccount` | `kubernetes.io.serviceaccount.name` |
| `k8s.pod` | `kubernetes.io.pod.name` |
| `k8s.cluster` | Pomerium's configured cluster name for the IdP |
| group `k8s:ns:<namespace>` | added to session.Groups |
| group `k8s:sa:<namespace>/<name>` | added to session.Groups |

---

## 9. Gotchas

- **Clock skew.** Default tolerance in most JWT libs is 60 s; SA tokens have
  nominal `iat`/`nbf`/`exp` and the kubelet does no client-side smoothing.
  Expose a small (≤ 2 min) leeway knob; refuse anything larger.
- **JWKS caching and rotation.** EKS rotates signing keys every ~7 days; AKS
  serves old+new keys for 24 h post-rotation. Cache TTL should be on the order
  of minutes, not hours, and Pomerium must refresh on `kid` miss (a JWT signed
  by a key not in the cache should trigger one re-fetch before rejection — this
  is the standard pattern but a known footgun if implemented as "reject and
  re-fetch on next request" with no negative-cache).
- **Self-managed clusters that rotate `--service-account-key-file`** can serve
  both old and new keys during a window; the JWKS endpoint returns both.
  Pomerium must accept any matching key in the JWKS, not just the first.
- **Deleted pod / SA.** JWKS path keeps accepting until `exp`. This is the
  largest gap vs TokenReview. Document it. For high-value routes, recommend
  TokenReview or very short `expirationSeconds`.
- **`warnafter` ≠ `exp`.** `kubernetes.io.warnafter` is a soft signal at ~80%
  of TTL telling the kubelet to rotate; **not** a validity boundary. Pomerium
  must ignore `warnafter` for accept/reject decisions.
- **`jti` replay detection.** Pre-1.32 tokens don't have a stable `jti`.
  Cross-replica replay detection isn't viable without `jti`. Advertise the
  limitation.
- **Pod-bound enforcement** requires KEP-4193 stable features (1.32+ for the
  claim shape, 1.33+ for node-binding). On older clusters, "pod-bound" is
  best-effort: claims are present but the apiserver does not enforce them on
  TokenReview. JWKS validation never enforces them.
- **`aud` is an array.** A token can have multiple audiences. Validators must
  accept "any one of the configured audiences matches any one of the token's
  audiences." Bog-standard but a frequent bug.
- **Anonymous discovery on the apiserver.**
  `/.well-known/openid-configuration` requires
  `system:service-account-issuer-discovery` by default. If Pomerium falls back
  to the in-cluster apiserver for JWKS, it must authenticate the discovery
  fetch with its own SA token — mildly recursive on bootstrap. EKS/GKE expose
  JWKS at a public URL outside the apiserver, sidestepping this.
- **AKS pre-1.34 without `--enable-oidc-issuer`** has no public JWKS at all;
  only TokenReview works.
- **EKS DNS in VPC-isolated setups:** `oidc.eks.<region>.amazonaws.com` is a
  public hostname; VPC endpoints can NXDOMAIN it. Operators add a Route 53
  conditional resolver. Worth a sentence in the docs.

---

## 10. Pros and cons (summary)

### Pros of supporting K8s SA tokens

- Zero client-code integration: anything that sets `Authorization: Bearer`
  works. No SDK changes.
- Natural fit for in-cluster ingress (apps inside the cluster talking through
  Pomerium to other apps inside or outside the cluster).
- Well-precedented (Vault, Istio, oauth2-proxy, kube-oidc-proxy, Dashboard).
- Identical mechanism across GKE / EKS / AKS / vanilla K8s.
- Audience binding gives operators a clean handle to scope which workloads can
  reach Pomerium.
- Slots into Pomerium's existing `VerifyIdentityToken` plumbing — small surface
  area to add.

### Cons / concerns

- mTLS with SPIFFE is arguably the "more correct" answer for in-cluster
  identity. Bearer JWTs are simpler but worse on revocation and slightly worse
  on theft replay.
- No `email`/`groups`/`name` claims — operators will need an opinion (Vault-
  style SA annotations, or namespace-as-group).
- `system:auth-delegator` is a big RBAC grant — JWKS-only avoids this, but
  loses pod-deletion revocation.
- The TokenReview path is an apiserver call on every request; APF limits and
  apiserver outage become Pomerium concerns.
- Audience-confusion footgun: easy to misconfigure into accepting the default
  apiserver audience. Validation must refuse this at startup.
- Multi-cluster TokenReview needs per-cluster reviewer JWTs — operationally
  heavier than the multi-cluster JWKS case.

---

## 10a. Generalizing to "any external JWT" — keep it in Pomerium

A K8s SA token is just a JWT with a particular `iss` and JWKS source. The
same validator that verifies it can verify:

- Azure Entra ID / Microsoft service-principal tokens (already supported)
- GitHub Actions OIDC (`iss=https://token.actions.githubusercontent.com`)
- GitLab CI job JWTs
- HashiCorp Vault OIDC issuer
- SPIFFE JWT-SVIDs
- Any internal IdP with a JWKS endpoint

The valuable framing is **not** "Pomerium supports K8s SA tokens" but
"Pomerium accepts any externally-issued JWT whose signature it can verify."
K8s-specific behavior (TokenReview, annotation mirroring, synthetic
namespace-groups) becomes an optional adapter layered on top of the generic
verifier — not the core feature.

### What about Envoy's `envoy.filters.http.jwt_authn`?

Initial reaction: offload JWT verification to Envoy's built-in `jwt_authn`
filter (this is what Istio's `RequestAuthentication` does under the hood).
**But Pomerium builds its own curated Envoy via
[`pomerium/envoy-custom`](https://github.com/pomerium/envoy-custom)**, and
`jwt_authn` is explicitly **not** compiled in.

Concrete evidence from `envoy-custom/bazel/envoy_build_config/extensions_build_config.bzl`
(152 extensions enabled, 123 disabled):

| Filter | Status |
|---|---|
| `envoy.filters.http.ext_authz` | ✓ enabled (line 163) |
| `envoy.filters.network.ext_authz` | ✓ enabled (line 227) |
| `envoy.filters.http.jwt_authn` | ✗ **disabled** (line 180) |
| `envoy.filters.http.oauth2` | ✗ disabled (line 189) |
| `envoy.filters.http.basic_auth` | ✗ disabled (line 149) |
| `envoy.filters.http.api_key_auth` | ✗ disabled (line 145) |
| `envoy.filters.http.gcp_authn` | ✗ disabled (line 167) |
| `envoy.http.injected_credentials.oauth2` | ✗ disabled (line 448) |

The pattern is deliberate: **Pomerium does all auth in its own Go process via
ext_authz, not in Envoy.** Adding `jwt_authn` would mean (a) uncommenting it
in `envoy-custom`, (b) coordinating a release of the custom Envoy binary, (c)
splitting auth logic across two processes, and (d) handling audit/UX/config-
reload semantics in two places. It's possible but cuts against the curated-
extension philosophy.

### What's already in our Go dep tree

`go.mod` already pulls in everything needed:

- `github.com/coreos/go-oidc/v3 v3.17.0` — OIDC discovery, JWKS fetching
  *with caching and key-rotation handling*, ID token verification
- `github.com/go-jose/go-jose/v3` and `/v4` — raw JWT/JWS primitives
- `github.com/lestrrat-go/jwx/v3` (indirect)
- `github.com/golang-jwt/jwt/v5` (indirect)

[`pkg/identity/oidc/oidc.go:462`](../pkg/identity/oidc/oidc.go) already calls
`internal.VerifyIDToken` which uses `go-oidc`'s `RemoteKeySet` — that **already
does JWKS fetching with caching, kid-miss re-fetch, and key-rotation
handling**. We don't need a new dependency; we just need a thinner config
shape (no OAuth2 client_id/client_secret) and a place to plug in K8s-flavored
claim handling.

### The revised plan: a generic JWT verifier inside Pomerium

```
HTTP Request
  ↓
envoy.filters.http.ext_authz       ───► sends CheckRequest to Pomerium authorize
  ↓
Pomerium authorize evaluator       ───► IncomingIDPTokenSessionCreator
                                        - extract Authorization: Bearer
                                        - dispatch by JWT iss → configured IdP
                                        - verify signature via go-oidc RemoteKeySet
                                          (or raw JWKS for non-OIDC issuers)
                                        - check aud / exp / nbf / alg allowlist
                                        - optional: TokenReview against k8s
                                        - mint Pomerium session, synthesize
                                          k8s.namespace / groups / etc.
                                        - run existing PPL unchanged
```

The split that matters: **verification = Pomerium's authorize service in Go;
ext_authz remains the only auth-adjacent Envoy filter.** Architecture stays
flat.

### What changes in code (small)

1. A new `external_jwt` or `jwt` IdP type — issuer URL + audiences + algorithm
   allowlist + JWKS URI (auto-discovered from `iss` if absent) + optional
   in-cluster CA bundle. No client_id/secret. Reuses `go-oidc`'s
   `RemoteKeySet` for the JWKS plumbing.
2. The existing `Authenticator.VerifyIdentityToken` slot already returns
   `map[string]any` of claims — no interface change needed.
3. Generalize `fillUserFromIDPClaims` in
   [`config/session.go:355`](../config/session.go) to support claim-mapping
   config (per-IdP), so K8s SA tokens (no `email`/`name`) and SPIFFE JWT-SVIDs
   (`spiffe://...` in `sub`) get sensible defaults.
4. Add an optional TokenReview adapter — a second `Authenticator` method or a
   new IdP subtype — for K8s-aware routes that want pod-deletion revocation.

This same code unlocks K8s SA tokens, GitHub Actions OIDC, GitLab CI tokens,
SPIFFE JWT-SVIDs, Vault OIDC issuers, and any custom IdP. K8s-specific
behavior (TokenReview, SA-annotation mirroring, synthetic `k8s:ns:*` groups)
becomes a thin adapter on top.

### If we ever want jwt_authn anyway

It's a one-line change in
[`envoy-custom/bazel/envoy_build_config/extensions_build_config.bzl:180`](https://github.com/pomerium/envoy-custom/blob/main/bazel/envoy_build_config/extensions_build_config.bzl)
plus a rebuild. The Go types in `go-control-plane/envoy@v1.37.0` are already
in our tree. But unless we're willing to split auth across two processes,
there's no concrete reason to take that on. Document it as a future option,
not a starting point.

---

## 11. Recommended design for Pomerium

A practical shape (mirroring Vault's two methods and Pomerium's existing IdP
abstraction):

1. **A new identity provider type** — `kubernetes` — that implements
   `identity.Authenticator`. It reuses the OIDC verifier for the JWKS path
   (since K8s issuers are OIDC-compatible) but adds a TokenReview path.
2. **Config knobs** on the IdP:
   - `issuer_url` (the cluster's `--service-account-issuer` value, or
     auto-discovered)
   - `jwks_uri` (override, e.g. for `https://kubernetes.default.svc/openid/v1/jwks`)
   - `verification_mode`: `jwks` (default) | `token_review` | `jwks_then_token_review`
   - `kubernetes_host` + `ca_cert` (for the TokenReview path; defaults to
     in-cluster auto-discovery via `KUBERNETES_SERVICE_HOST`)
   - `token_reviewer_jwt` (defaults to Pomerium's own projected SA token if
     `automountServiceAccountToken` is true)
   - `required_audiences` (must be non-empty; startup error if it overlaps
     with the apiserver default or known Workload Identity audiences)
   - `allowed_algorithms` (default: `RS256, ES256, PS256`)
   - `clock_skew_leeway` (default: 60 s, max 120 s)
   - `claim_mapping`: configurable map from JWT claim → Pomerium session field
     (default: `sub` → user_id; `kubernetes.io.namespace` → group
     `k8s:ns:<ns>`; SA annotations matching a configurable prefix → claims)
3. **Refuse to accept the default API-server audience** at config-load time.
   This is the audience-confusion guardrail.
4. **`bearer_token_format: idp_identity_token`** on the route, just like
   today's Azure flow. No new format enum needed; SA tokens are JWTs and slot
   into the existing path.
5. **Documentation pattern** — produce an end-to-end example that includes:
   - Pomerium's own Deployment + ServiceAccount + RBAC (auth-delegator only if
     TokenReview is enabled)
   - A sample workload pod with a `projected` volume that requests the
     Pomerium-specific audience
   - A sample policy that grants by namespace or SA name
6. **Audit logging** — every accepted SA token yields a structured log line
   with `sub`, `aud`, `iss`, `kubernetes.io.namespace`, `kubernetes.io.pod.name`,
   `jti` (where present). `jti` is critical for replay detection — record it.

This is a small additive change to the existing inbound-token flow, not a new
parallel system.

---

## 12. References

### Kubernetes core

- [Kubernetes: Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Kubernetes: Managing Service Accounts (admin)](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Kubernetes: Authenticating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes TokenReview v1 API reference](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
- [k8s.io/api/authentication/v1 (Go package)](https://pkg.go.dev/k8s.io/api/authentication/v1)

### Kubernetes Enhancement Proposals (KEPs)

- [KEP-1205: Bound Service Account Tokens](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/1205-bound-service-account-tokens/README.md)
- [KEP-1393: OIDC discovery for service account issuer](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/1393-oidc-discovery)
- [KEP-4193: Bound Service Account Token Improvements](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/4193-bound-service-account-token-improvements)

### Cloud providers

- GKE: [About Workload Identity Federation for GKE](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
- GKE: [Configure Workload Identity Federation with Kubernetes](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-kubernetes)
- GKE: [Kubernetes Bound Service Account Tokens (blog)](https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-bound-service-account-tokens)
- EKS: [IAM Roles for Service Accounts technical overview](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts-technical-overview.html)
- EKS: [Fetch signing keys to validate OIDC tokens](https://docs.aws.amazon.com/eks/latest/userguide/irsa-fetch-keys.html)
- EKS: [Configure Pods to use a service account](https://docs.aws.amazon.com/eks/latest/userguide/pod-configuration.html)
- EKS: [amazon-eks-pod-identity-webhook](https://github.com/aws/amazon-eks-pod-identity-webhook)
- AKS: [Create an OIDC Provider for your AKS cluster](https://learn.microsoft.com/en-us/azure/aks/use-oidc-issuer)
- AKS: [Use a Microsoft Entra Workload ID on AKS](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)

### Prior art

- [HashiCorp Vault Kubernetes auth method](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
- [HashiCorp Vault JWT/OIDC auth — Kubernetes provider](https://developer.hashicorp.com/vault/docs/auth/jwt/oidc-providers/kubernetes)
- [HashiCorp KB: Vault JWT auth with EKS/AKS public signing keys](https://support.hashicorp.com/hc/en-us/articles/28072525620499-Vault-JWT-auth-with-public-signing-keys-in-EKS-and-AKS)
- [Istio RequestAuthentication reference](https://istio.io/latest/docs/reference/config/security/request_authentication/)
- [Istio security concepts](https://istio.io/latest/docs/concepts/security/)
- [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
- [Ian Unruh: OAuth2-Proxy with Kubernetes Service Accounts](https://www.ianunruh.com/posts/oauth2-proxy-with-k8s-service-accounts/)
- [jetstack/kube-oidc-proxy](https://github.com/jetstack/kube-oidc-proxy)
- [Linkerd: Using Kubernetes's new Bound Service Account Tokens](https://linkerd.io/2021/12/28/using-kubernetess-new-bound-service-account-tokens-for-secure-workload-identity/)
- [Linkerd's automated identity pipeline (SPIFFE)](https://dev.to/gtrekter/from-trust-anchors-to-spiffe-ids-understanding-linkerds-automated-identity-pipeline-37k9)
- [Kuadrant / Authorino: TokenReview worked example](https://docs.kuadrant.io/latest/authorino/docs/user-guides/kubernetes-tokenreview/)
- [seankhliao: TokenRequest and TokenReview walkthrough](https://seankhliao.com/blog/12023-07-05-k8s-tokenrequest-tokenreview/)

### Security

- [PortSwigger: JWT algorithm confusion attacks](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [WorkOS: JWT algorithm confusion — how to prevent](https://workos.com/blog/jwt-algorithm-confusion-attacks)
- [Keycloak `jwks_uri` SSRF issue](https://github.com/keycloak/keycloak/issues/45645)
- [Sigstore Fulcio MetaIssuer SSRF advisory (GHSA-59jp-pj84-45mr)](https://github.com/sigstore/fulcio/security/advisories/GHSA-59jp-pj84-45mr)
- [PortSwigger Research: Hidden OAuth attack vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [GitGuardian: Risks of long-lived K8s SA tokens](https://blog.gitguardian.com/understanding-the-risks-of-long-lived-kubernetes-service-account-tokens/)
- [Kubernetes Dashboard hardening guide (2026)](https://dev.to/matheus_releaserun/securing-the-kubernetes-dashboard-a-hardening-guide-for-2026-3km7)

### Operational

- [k/k issue 71811: TokenReview API timeouts under load](https://github.com/kubernetes/kubernetes/issues/71811)
- [k/k issue 69893: Update authenticators to handle audience semantics](https://github.com/kubernetes/kubernetes/issues/69893)
- [Kubernetes API Priority and Fairness](https://kubernetes.io/docs/concepts/cluster-administration/flow-control/)
- [psaggu: Is Kubernetes ServiceAccount a JWT token? And how to verify it?](https://psaggu.com/2025/12/19/k8s-serviceaccount-jwt.html)

### Envoy

- [`envoy.filters.http.jwt_authn` filter reference](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter)
- [`JwtAuthentication` proto (v3)](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/jwt_authn/v3/config.proto)
- [Go types in `go-control-plane`](https://pkg.go.dev/github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3)

### K3s / RKE2 / k3d

- [docs.k3s.io — Architecture](https://docs.k3s.io/architecture)
- [docs.k3s.io — Server CLI](https://docs.k3s.io/cli/server)
- [docs.k3s.io — Certificate CLI](https://docs.k3s.io/cli/certificate)
- [docs.k3s.io — Installation Configuration](https://docs.k3s.io/installation/configuration)
- [`pkg/daemons/control/server.go` (k3s-io/k3s)](https://github.com/k3s-io/k3s/blob/master/pkg/daemons/control/server.go)
- [SUSE KB: Update kube-apiserver args in RKE2 and K3s](https://support.scc.suse.com/s/kb/How-to-Update-or-Add-Arguments-to-the-kube-apiserver-in-RKE2-and-K3s-Clusters)
- [RKE2 Server Configuration](https://docs.rke2.io/reference/server_config)
- [k3d-io/k3d#1187 — kubeapi-server flag pass-through](https://github.com/k3d-io/k3d/issues/1187)

### Existing Pomerium code referenced

- [`config/session.go`](../config/session.go) — `IncomingIDPTokenSessionCreator`, `GetIncomingIDPAccessTokenForPolicy`, `GetIncomingIDPIdentityTokenForPolicy`
- [`authenticate/handlers_verify.go`](../authenticate/handlers_verify.go) — `/.pomerium/verify-access-token` and `/.pomerium/verify-identity-token` endpoints
- [`pkg/identity/providers.go`](../pkg/identity/providers.go) — `Authenticator` interface with `VerifyAccessToken` / `VerifyIdentityToken`
- [`pkg/identity/oidc/oidc.go`](../pkg/identity/oidc/oidc.go) — reference OIDC verifier implementation
- [`pkg/grpc/config/config.proto`](../pkg/grpc/config/config.proto) — `BearerTokenFormat` enum
