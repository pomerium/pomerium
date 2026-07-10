# Native PostgreSQL Access

## Product contract

Native PostgreSQL access follows the SSH packaging model, but it does not share
SSH's protocol implementation.

- Core owns the PostgreSQL listener, SNI route selection, Pomerium identity,
  session authorization, and one-to-one protocol relay.
- Core access ultimately permits client-supplied PostgreSQL credentials.
- Enterprise managed access adds upstream credential injection.
- Query recording, row caps, step-up, and statement-class policy are separate
  Enterprise query-governance work. They are not enabled or advertised by this
  release.

The implementation is on the release/GA track. Preview labeling does not lower
the security bar for identity, credentials, authorization, TLS, or protocol
isolation.

## Upgrade note

The earlier preview exposed `postgres_username`, `postgres_database`,
`postgres_application_name`, and `postgres_statement_class` PPL criteria. Those
criteria were removed because the Core path could not authenticate the
client-supplied metadata or enforce statement classification as a security
boundary. Existing policies that reference any of them are invalid after this
upgrade and must be rewritten to authorize the PostgreSQL route and Pomerium
session identity using supported criteria. There is deliberately no
compatibility registration that silently accepts or ignores the old criteria;
statement-class policy returns only with the future Enterprise query-governance
implementation.

## Release trains

The work ships in two dependency-ordered trains.

### Managed access

The first train makes the already-built managed credential path releasable:

1. Console publishes short-lived proof of the licensed managed-PostgreSQL
   capability through its existing authenticated DataBroker relationship.
2. Core independently validates the proof. Configuration flags, extension
   presence, and unsigned Settings fields cannot create the capability.
3. `pomerium-cli db login` creates an ephemeral self-signed Ed25519 certificate
   and binds its fingerprint to a freshly verified Pomerium session.
4. Core injects a route-owned upstream password only while the capability,
   binding, web session, route revision, and policy remain valid.
5. A neutral bounded relay carries ordinary PostgreSQL traffic without query
   classification, query recording, row caps, or step-up behavior.

Managed credential injection is not an OSS fallback. Loss or expiry of the
capability rejects new managed sessions and closes active ones no later than
the next operation boundary or periodic reauthorization.

### Client-supplied access

The second train will add the Core authentication relay. It must support
upstream `AuthenticationOk`, SCRAM-SHA-256, MD5, and cleartext password
authentication only across verified upstream TLS. SCRAM-SHA-256-PLUS will
remain unsupported because channel binding cannot be relayed across two
independent TLS connections.

Startup parameters in that train must remain compatible with normal libpq, pgx,
and JDBC use. Parameters that change the connection's security role or mode,
including replication and unsafe `options`, must be denied.

## Identity invariant

`db login` performs a fresh browser login and submits a constrained client
certificate over an exact Pomerium bearer-authenticated endpoint. Core creates
only a `ProtocolPostgres` session binding. It never creates a persistent
identity binding for this flow.

The certificate is a non-CA Ed25519 leaf with client-auth usage, a route DNS
SAN, and a lifetime of at most one hour. Its binding expires at the earliest of
the certificate, web session, and server one-hour limit. At connection time,
TLS proves possession of the private key; Core validates the self-signature,
shape, SNI/SAN, fingerprint, binding protocol, route, session, user, and
expiry. The connection closes at the authoritative expiry rather than waiting
for a later reauthorization tick.

The direct POST flow deliberately does not claim SSH-style browser display of
the fingerprint. A stolen fresh bearer can bind an attacker's certificate for
the remaining short issuance window. The endpoint therefore accepts only an
exact bearer header, checks issuer, audience, a five-minute issuance window,
and the current DataBroker session, and rejects cookie or query authentication.
The request also proves possession of the submitted certificate key over the
exact bearer token and route, which prevents certificate substitution or a
public certificate fingerprint from overwriting another session's binding.

## Enterprise capability invariant

Console derives capability from the real Keygen license state. For online
licenses it requests a nonce-, product-, installation-, and capability-scoped
validation response. The signed response contains the license key, so it is
never stored in cleartext. Console encrypts it with versioned authenticated
encryption bound to the installation and DataBroker record identity.

Core decrypts only in memory and independently verifies the Keygen Ed25519
response signature, body digest, response date, nonce, product, installation
fingerprint, capability scope, validation result, metadata, and license expiry.
It caps the usable proof to the signed response date plus five minutes. The
DataBroker record TTL is not itself proof of entitlement.

Offline evidence must provide the same capability and installation binding
using a distributable signed license proof. Offline validation is an explicit
Console deployment mode and cannot provide vendor-side live revocation before
the signed offline license expires; local capability, route, session, and policy
revocation still apply. A non-release or no-check build does not publish managed
access by default.

## Protocol invariant

The production relay has no SQL classifier. It forwards bounded PostgreSQL
messages in both directions, does not buffer an extended batch, preserves COPY,
FunctionCall, Flush, Sync recovery, pipelining, and transaction error behavior,
and maps one downstream connection to one upstream connection.

The managed database role is therefore the per-statement security boundary.
The relay forwards any SQL the role permits; it does not block role changes,
multi-statement requests, COPY programs, or other SQL forms. Operators must use
a least-privilege role and must not treat this release as a SQL firewall.

It reauthorizes before simple Query, FunctionCall, the first extended operation
after Sync, and Execute, as well as periodically. Revocation closes the
connection instead of synthesizing a partial extended-protocol recovery.
Because closure can occur in any PostgreSQL protocol state, the client may see
a TCP reset rather than an ErrorResponse. After capability evidence is removed
or expires in Core, the next operation boundary or periodic reauthorization
ends the session; the production periodic interval bounds that Core-local
residual window to approximately one minute. Vendor-side online revocation also
waits for Console's validation refresh, and a transient validation outage
retains only the last signed proof until its cryptographic expiry.
When either direction exits, both sockets close, the cancel-key mapping is
removed, reauthorization stops, and connection capacity is released exactly
once.

The previous classifier/recording/row-cap relay remains unreachable from the
production constructor while it is reshaped under an experimental query-guard
owner. No flag, configuration field, or exported API may enable it.

## Configuration and secret invariant

A PostgreSQL route has one credential-free upstream destination and explicit
PostgreSQL settings. Managed username, database, and password do not live in
`Route.to`; the password is a sensitive protobuf field. Userinfo and connection
options in the destination URL are rejected.

Verified upstream TLS is the default. An insecure mode is allowed only through
an explicit setting for a literal loopback destination. Environment variables
must never supply or change the route's upstream target, credentials, or TLS
mode.

Secrets are retained only in authenticated runtime configuration. They are
redacted from policy strings, URL strings, validation errors, debug/config
presentation, logs, recording errors, and client-visible PostgreSQL errors.

## Lifecycle invariant

The PostgreSQL listener is supervised independently from the main process.
Initial bind failure degrades PostgreSQL health and retries; it does not stop
Pomerium. Address or TLS changes publish a fully validated snapshot and retain
the last-known-good listener when a replacement cannot bind or validate, unless
the Enterprise authority material changed. A failed authority rotation closes
the old listener rather than mixing new authority with old credentials.
Disabling the feature closes the listener and active sessions.

Startup, authentication, and upstream dialing have deadlines. The idle bound
measures time spent waiting for client protocol input; it does not terminate a
silent active database operation. ReadyForQuery, extended-protocol completion,
and COPY input transitions determine when the client is expected to speak.
Absolute connection lifetime still bounds every state. A shared connection cap
applies across listener generations so hot reload cannot multiply
unauthenticated work.

## Evidence gates

Managed access is not ready until tests prove:

- missing, expired, replayed, cross-installation, and malformed entitlement
  evidence fails closed, including active-session revocation;
- actual CLI browser login creates a route-scoped binding and generated libpq
  material connects through the native listener to real PostgreSQL;
- unbound, substituted, wrong-route, expired, and revoked certificates fail;
- a canary password is absent from every presentation and client-error surface;
- real PostgreSQL traffic covers simple, prepared/extended, pipelined, COPY,
  cancellation, malformed/oversized messages, half-closes, and shutdown;
- listener flag/address/TLS transitions, failed replacement, connection caps,
  deadlines, goroutine cleanup, file-descriptor cleanup, and race tests pass.

The external CLI gate is named `make test-postgres-cli-e2e`. It is deliberately
Linux-only, requires `POMERIUM_CLI_BIN` to point at the separately built CLI,
and treats Docker-provider skips as failures. Release evidence must capture a
non-skipped run of that target; the ordinary unit-test target does not replace
it.

Historical PoC recordings do not satisfy these gates. The lost Vault/transcript
harness cannot be rerun, and Vault dynamic credentials, durable recording, row
caps, live query enforcement, and redacted transcript rendering are not
implemented by this branch.

## Deferred query governance

GA query governance requires PostgreSQL grammar fidelity. `pg_query_go` depends
on cgo and libpg_query while Core release builds use `CGO_ENABLED=0`; the
Cockroach-derived pure-Go parser and the current lexer are not substitutes for
a PostgreSQL security boundary. The deferred Enterprise track must resolve that
build architecture before it claims statement classes, role-change blocking,
row caps, step-up, recording, or enforcement.

## Implementation order

1. Core proof, identity, HTTP, and neutral-relay contracts.
2. Console capability proof publisher and Core capability consumer.
3. CLI certificate, browser login, binding POST, and libpq material.
4. Managed route schema, password migration/redaction, runtime entitlement
   gating, and configuration snapshots.
5. Listener supervision and resource hardening.
6. End-to-end, race, build, lint, and captured independent review gates.
7. Client-supplied Core authentication relay.

## Dependency order

Core owns the shared API and generated modules, so its reviewed revision is the
publication root for this train. Console and CLI must pin the Core root,
configuration, and DataBroker modules to that same revision and pass without a
workspace override before they merge. The Core client-authentication train
starts from that checkpoint rather than being mixed into the managed release.

Do not reintroduce a local Enterprise toggle, a Core-to-Console polling client,
CA-issued client certificates, public PostgreSQL query criteria, or a production
switch for the old query guard. Client-supplied authentication follows as its
own train.
