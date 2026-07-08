# Native Postgres Preview

## Summary

This branch adds a flag-gated preview of native `postgres://` routes in
Pomerium Core. A standard Postgres client can connect to Pomerium over mTLS,
Pomerium binds the client certificate to a Pomerium session, authorizes the
route with the existing policy evaluator, injects upstream Postgres credentials,
and proxies the Postgres wire protocol to a real upstream database.

This is a vertical slice for product and design review. It is not GA.

## What The Slice Proves

- `postgres://` routes are first-class config objects behind
  `RuntimeFlagPostgres`.
- Core can run a native Postgres listener without putting Postgres traffic
  through Envoy HTTP route generation.
- Route selection uses the Postgres client's TLS SNI.
- Client identity is tied to a short-lived client certificate and
  `SessionBinding`, following the same identity model as native SSH.
- The upstream Postgres password is not sent to the client; Core injects it
  from route config when opening the upstream connection.
- Query authorization hooks run before statements reach upstream.
- Real Docker-backed tests exercise Postgres, mTLS, the Core adapter, the
  authorizer, and a `psql` client path.

## Why Go-Native Instead Of Envoy

SSH lives in Envoy because the SSH implementation needs a protocol-aware
datapath extension for SSH handshakes, channel management, forwarding, and the
recording tap. Postgres is different for this preview:

- The risky Postgres logic is query-protocol correlation: Parse, Bind,
  Execute, Describe, partial batches, row caps, and cancel behavior.
- The Go implementation uses `pgproto3`, which is already available through
  Pomerium's existing `pgx` dependency.
- Porting the proven state machine into a custom Envoy C++ codec would add a
  second protocol parser and Bazel/plugin surface before improving the customer
  workflow.
- The Core path reuses the existing evaluator, databroker session model, TLS
  certificate inventory, and integration test stack.

An Envoy codec remains a possible future implementation if one-dataplane
consistency becomes more important than the rewrite cost. This preview treats
the Go engine as the implementation and the test oracle.

## What SSH Still Teaches

The SSH work provides the reusable product model:

- protocol-native listener;
- browser-authenticated identity bound to a client credential;
- route-level authorization through Pomerium policy;
- live session state through `SessionBinding`;
- commercial recording and replay as a separate product layer.

It does not require the Postgres datapath to live in Envoy. First-class support
means shared policy, identity, configuration, testing, and lifecycle ownership,
not identical process placement.

## Open Product Decision

The current preview requires upstream credentials on every Postgres route and
uses those credentials for managed injection. That makes credential injection a
Core behavior today.

The product decision before merge to a release branch is whether native Postgres
ships as:

- an Enterprise PAM feature from the start, where credential injection,
  revocation, query enforcement, and recording are gated together; or
- an OSS access-plane feature with a separate client-supplied-credential mode,
  while managed credential injection, revocation, query enforcement, and
  recording remain Enterprise.

Until that decision is made, this branch should stay a preview/draft.

## Security Findings Fixed During Review

The preview was audited before this draft. The following merge-blocking issues
were fixed in the implementation and covered by regression tests:

- stale `pgconn` fallback configuration could have retried with route
  credentials against an unintended no-TLS fallback target;
- mixed extended-protocol batches could authorize an allowed Execute while
  leaking metadata for a denied Parse or Describe;
- extended Execute cycles could defer reauthorization until the periodic timer;
- oversized frontend messages or pre-Sync extended batches could grow proxy
  memory without a product cap.

## GA Gates

- Replace the lexical SQL classifier with a PostgreSQL grammar-backed parser
  such as `pg_query_go` before relying on deeper query semantics.
- Define the Enterprise evidence model for query recording: encryption,
  retention, access control, audit-of-audit, and Console replay.
- Add the CLI user experience for `pomerium-cli db login` and generated libpq
  connection material.
- Resolve the OSS versus Enterprise credential-injection split.
- Decide the recording failure mode for Enterprise query evidence. This preview
  records through a best-effort engine hook; durable, fail-closed evidence is a
  GA product requirement, not something the preview claims.
- Define hot-start lifecycle semantics for `postgres_address`. In this preview,
  disabling the runtime flag or changing the listen address stops the listener;
  re-enabling or rebinding requires a process restart.
