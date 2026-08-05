// testcontainers orchestration for the upstream TLS/mTLS e2e stack.
// Modeled on internal/acceptance/suites/downstream-mtls/setup/containers.ts.
//
// Topology: one Docker network on which every service is reachable by an alias.
// The IdP + authenticate names are *.localhost.pomerium.io (public DNS ->
// 127.0.0.1) so the OIDC issuer URL is byte-identical from the browser
// (front-channel) and from inside Pomerium (back-channel). The upstream servers
// are reached only in-network by short aliases (upstream, upstream-tls, ...);
// those aliases double as the default SNI / verification name for each route.
//
//   keycloak.localhost.pomerium.io   HTTP  8080  (reuses ../../keycloak realm import)
//   upstream                         HTTP  8000  (pomerium/verify; plain-HTTP control route)
//   upstream-tls                     HTTPS 4433  (Node echo; plain server TLS)
//   upstream-mtls                    HTTPS 4433  (Node echo; requires a client cert)
//   upstream-sni                     HTTPS 4433  (Node echo; switches cert on SNI)
//   upstream-reneg                   HTTPS 4433  (Node echo; server-initiated renegotiation)
//   {authenticate,<route>}.localhost.pomerium.io HTTPS 8443 (official pomerium image)
//
// Lifecycle: everything boots once in Playwright's global setup - the network,
// Keycloak, all upstreams, AND a single shared Pomerium serving one config with
// a route per test variant (setup/pomerium-config.ts mainConfigFile). The
// network name is handed to the workers via process.env. Specs don't start
// Pomerium; they navigate as the logged-in user (workers: 1, so the fixed 8443
// port has one owner). Only the config-error path boots extra, port-less,
// short-lived Pomerium containers (startPomeriumExpectingConfigError).

import * as path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import {
  GenericContainer,
  Network,
  Wait,
  type StartedTestContainer,
  type StartedNetwork,
} from "testcontainers";
import { ensureCerts, type CertPaths } from "./certs.js";
import {
  ALL_ROUTE_HOSTNAMES,
  AUTHENTICATE_HOSTNAME,
  CERTS_DIR,
  KEYCLOAK_HOSTNAME,
  MTLS_UPSTREAM_HOST,
  RENEG_UPSTREAM_HOST,
  SNI_BACKEND_NAME,
  SNI_UPSTREAM_HOST,
  SUITE_DIR,
  TLS_UPSTREAM_HOST,
  TLS_UPSTREAM_PORT,
} from "./constants.js";

const ACCEPTANCE_DIR = path.resolve(SUITE_DIR, "..", "..");
const KEYCLOAK_IMPORT_DIR = path.join(ACCEPTANCE_DIR, "keycloak");
const UPSTREAM_SERVER_JS = path.join(SUITE_DIR, "upstream", "server.js");

const KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.5.2";
// pomerium/verify: plain-HTTP control upstream for the OIDC smoke test and the
// pass_identity_headers baseline. Pinned to the same digest the parent
// acceptance suite uses; override with VERIFY_IMAGE.
const VERIFY_IMAGE =
  process.env.VERIFY_IMAGE ||
  "pomerium/verify@sha256:6d9dd40deae8d3ae7517485febf6fd4e7de2692e9dc1a2859c00e3426559af96";
// First-party echo upstream base image (server.js is bind-mounted in). node
// core modules only, so any recent node:alpine works. Pinned by multi-arch
// index digest for reproducibility; override with NODE_IMAGE.
const NODE_IMAGE =
  process.env.NODE_IMAGE ||
  "node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2";
const POMERIUM_IMAGE = process.env.POMERIUM_IMAGE || "pomerium/pomerium:main";

const STARTUP_TIMEOUT_MS = 240_000;
// Pomerium boots in ~2s; keep its startup wait WELL below the Playwright test
// timeout (120s) so a failed wait strategy cleans the container up instead of
// being abandoned mid-start (which leaks the fixed 8443 port binding).
const POMERIUM_STARTUP_TIMEOUT_MS = 90_000;
// A fatal-config container exits in a few seconds; this only bites if a config
// wrongly starts clean (a test failure), so keep it modest.
const CONFIG_ERROR_TIMEOUT_MS = 45_000;
const LOGS = !!process.env.UPSTREAM_TLS_E2E_LOGS;

// Env var carrying the shared network name from global setup to the workers.
const NETWORK_ENV = "UPSTREAM_TLS_E2E_NETWORK";

// In-container paths of the mounted upstream PKI (see scripts/gen-certs.sh).
const C = {
  serverTlsCert: "/certs/upstream/server-tls.crt",
  serverTlsKey: "/certs/upstream/server-tls.key",
  serverMtlsCert: "/certs/upstream/server-mtls.crt",
  serverMtlsKey: "/certs/upstream/server-mtls.key",
  serverRenegCert: "/certs/upstream/server-reneg.crt",
  serverRenegKey: "/certs/upstream/server-reneg.key",
  serverSniDecoyCert: "/certs/upstream/server-sni-decoy.crt",
  serverSniDecoyKey: "/certs/upstream/server-sni-decoy.key",
  serverSniBackendCert: "/certs/upstream/server-sni-backend.crt",
  serverSniBackendKey: "/certs/upstream/server-sni-backend.key",
  clientCA: "/certs/upstream/client-ca.crt",
} as const;

export interface BaseStack {
  network: StartedNetwork;
  containers: StartedTestContainer[];
}

let base: BaseStack | undefined;
let certsCache: CertPaths | undefined;

function certs(): CertPaths {
  certsCache ??= ensureCerts();
  return certsCache;
}

function logConsumer(prefix: string) {
  return (stream: { on(event: "data", cb: (line: string) => void): void }) => {
    stream.on("data", (line) => process.stdout.write(`[${prefix}] ${line}`));
  };
}

function withLogs(c: GenericContainer, prefix: string): GenericContainer {
  return LOGS ? c.withLogConsumer(logConsumer(prefix)) : c;
}

/** A Node echo upstream (server.js bind-mounted) with mode-specific env. */
function nodeUpstream(
  network: StartedNetwork,
  alias: string,
  env: Record<string, string>,
): GenericContainer {
  return withLogs(
    new GenericContainer(NODE_IMAGE)
      .withNetwork(network)
      .withNetworkAliases(alias)
      .withUser("node")
      .withEnvironment({ PORT: String(TLS_UPSTREAM_PORT), ...env })
      .withBindMounts([
        { source: UPSTREAM_SERVER_JS, target: "/app/server.js", mode: "ro" },
        { source: CERTS_DIR, target: "/certs", mode: "ro" },
      ])
      .withCommand(["node", "/app/server.js"])
      .withWaitStrategy(Wait.forLogMessage(/upstream-echo .* listening/))
      .withStartupTimeout(STARTUP_TIMEOUT_MS),
    alias,
  );
}

/** Boot the config-invariant services. Called from Playwright global setup. */
export async function startBaseStack(): Promise<BaseStack> {
  if (base) return base;

  certs(); // generate the PKI up front so workers hit the freshness fast path
  const network = await new Network().start();

  try {
    // --- Keycloak (IdP) ----------------------------------------------------
    const keycloak = withLogs(
      new GenericContainer(KEYCLOAK_IMAGE)
        .withNetwork(network)
        .withNetworkAliases(KEYCLOAK_HOSTNAME)
        .withExposedPorts({ container: 8080, host: 8080 }, 9000)
        .withEnvironment({
          KC_BOOTSTRAP_ADMIN_USERNAME: "admin",
          KC_BOOTSTRAP_ADMIN_PASSWORD: "admin",
          KC_HTTP_ENABLED: "true",
          KC_HOSTNAME: KEYCLOAK_HOSTNAME,
          KC_HOSTNAME_STRICT: "false",
          KC_PROXY_HEADERS: "xforwarded",
        })
        .withBindMounts([
          { source: KEYCLOAK_IMPORT_DIR, target: "/opt/keycloak/data/import", mode: "ro" },
        ])
        .withCommand(["start-dev", "--import-realm", "--health-enabled=true", "--http-port=8080"])
        .withWaitStrategy(Wait.forHttp("/health/ready", 9000).forStatusCode(200))
        .withStartupTimeout(STARTUP_TIMEOUT_MS),
      "keycloak",
    );

    // --- Control upstream (pomerium/verify, plain HTTP) --------------------
    const verify = withLogs(
      new GenericContainer(VERIFY_IMAGE)
        .withNetwork(network)
        .withNetworkAliases("upstream")
        .withWaitStrategy(Wait.forLogMessage(/starting http server/))
        .withStartupTimeout(STARTUP_TIMEOUT_MS),
      "upstream",
    );

    // --- TLS/mTLS echo upstreams (first-party server.js) -------------------
    const upstreamTls = nodeUpstream(network, TLS_UPSTREAM_HOST, {
      MODE: "tls",
      CERT: C.serverTlsCert,
      KEY: C.serverTlsKey,
    });
    const upstreamMtls = nodeUpstream(network, MTLS_UPSTREAM_HOST, {
      MODE: "mtls",
      CERT: C.serverMtlsCert,
      KEY: C.serverMtlsKey,
      CA: C.clientCA,
    });
    const upstreamSni = nodeUpstream(network, SNI_UPSTREAM_HOST, {
      MODE: "sni",
      CERT: C.serverSniDecoyCert,
      KEY: C.serverSniDecoyKey,
      CERT2: C.serverSniBackendCert,
      KEY2: C.serverSniBackendKey,
      SNI_MATCH: SNI_BACKEND_NAME,
    });
    const upstreamReneg = nodeUpstream(network, RENEG_UPSTREAM_HOST, {
      MODE: "reneg",
      CERT: C.serverRenegCert,
      KEY: C.serverRenegKey,
    });

    // Boot concurrently (Keycloak dominates the wall time); clean up whatever
    // started if any fail.
    const defs = [keycloak, verify, upstreamTls, upstreamMtls, upstreamSni, upstreamReneg];
    const results = await Promise.allSettled(defs.map((c) => c.start()));
    const started = results
      .filter((r): r is PromiseFulfilledResult<StartedTestContainer> => r.status === "fulfilled")
      .map((r) => r.value);
    const rejected = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
    if (rejected) {
      await Promise.allSettled(started.map((c) => c.stop()));
      throw rejected.reason;
    }

    // Hand the network to the worker processes (they inherit process.env).
    process.env[NETWORK_ENV] = network.getName();

    base = { network, containers: started };
    return base;
  } catch (err) {
    await network.stop().catch(() => {});
    throw err;
  }
}

/** Stop the config-invariant services. Called from Playwright global teardown. */
export async function stopBaseStack(): Promise<void> {
  if (!base) return;
  const { network, containers } = base;
  base = undefined;
  await Promise.allSettled(containers.map((c) => c.stop()));
  await network.stop().catch(() => {});
}

export interface PomeriumOptions {
  /** Host path of the config file to mount at /pomerium/config.yaml. */
  configFile: string;
  /** Extra environment variables. */
  env?: Record<string, string>;
}

export interface StartedPomerium {
  stop(): Promise<void>;
}

let currentPomerium: StartedPomerium | undefined;

// Build a Pomerium container on the shared network (config + certs mounted).
// Callers add their own divergent concerns: the serving instance adds network
// aliases + the 8443 host port + an HTTP wait; the config-error instance adds
// neither (so it never serves nor shadows the serving instance's aliases). Pass
// `lines` to capture stdout/stderr - only the config-error path reads them back;
// the healthy path passes nothing (and streams only when LOGS is set).
function pomeriumContainer(
  networkName: string,
  configFile: string,
  env: Record<string, string>,
  lines?: string[],
): GenericContainer {
  const container = new GenericContainer(POMERIUM_IMAGE)
    .withNetworkMode(networkName)
    .withEnvironment(env)
    .withBindMounts([
      { source: configFile, target: "/pomerium/config.yaml", mode: "ro" },
      { source: certs().certsDir, target: "/certs", mode: "ro" },
    ]);
  if (!lines && !LOGS) return container;
  return container.withLogConsumer((stream) => {
    stream.on("data", (line: string) => {
      lines?.push(line);
      if (LOGS) process.stdout.write(`[pomerium] ${line}`);
    });
  });
}

function requireNetwork(): string {
  const networkName = process.env[NETWORK_ENV];
  if (!networkName) {
    throw new Error(
      `${NETWORK_ENV} is not set - the base stack (global setup) must run before startPomerium`,
    );
  }
  return networkName;
}

/**
 * Start the shared Pomerium container (official image) bound to host port 8443.
 * Called once from global setup; any previous instance is stopped first for
 * safety. Reaches the shared network via the name exported by startBaseStack.
 */
export async function startPomerium(opts: PomeriumOptions): Promise<StartedPomerium> {
  const networkName = requireNetwork();
  if (currentPomerium) await currentPomerium.stop();

  const container = pomeriumContainer(networkName, opts.configFile, opts.env ?? {})
    .withNetworkAliases(AUTHENTICATE_HOSTNAME, ...ALL_ROUTE_HOSTNAMES)
    .withExposedPorts({ container: 8443, host: 8443 })
    // /healthz is exempt from route policy, so this probe needs no auth. Keep
    // the startup wait below the Playwright test timeout so a failure cleans up.
    .withWaitStrategy(Wait.forHttp("/healthz", 8443).usingTls().allowInsecure().forStatusCode(200))
    .withStartupTimeout(POMERIUM_STARTUP_TIMEOUT_MS);

  // Docker can hold the 8443 binding briefly after a container stops, so a
  // container lingering from a previous run (or a re-invoked start) can surface
  // "port is already allocated" - retry briefly to let the binding release.
  const startedContainer = await (async () => {
    for (let attempt = 1; ; attempt++) {
      try {
        return await container.start();
      } catch (err) {
        const message = String(err);
        if (attempt >= 10 || !/port is already allocated/.test(message)) throw err;
        await sleep(1_000);
      }
    }
  })();

  const started: StartedPomerium = {
    stop: async () => {
      if (currentPomerium === started) currentPomerium = undefined;
      await startedContainer.stop().catch(() => {});
    },
  };
  currentPomerium = started;
  return started;
}

/** Stop the shared Pomerium (started in global setup). Used in global teardown. */
export async function stopCurrentPomerium(): Promise<void> {
  if (currentPomerium) await currentPomerium.stop();
}

/**
 * Start a Pomerium container that is EXPECTED to fail config validation on
 * boot (log.Fatal + exit). Returns the captured log lines once the error
 * pattern is seen (or the container exits). Deliberately binds NO host port, so
 * it never contends for 8443 with a healthy per-spec instance.
 */
export async function startPomeriumExpectingConfigError(opts: {
  configFile: string;
  errorPattern: RegExp;
  env?: Record<string, string>;
}): Promise<string[]> {
  const networkName = requireNetwork();
  const lines: string[] = [];
  // No aliases and no host port (never calls withNetworkAliases/withExposedPorts):
  // this container never serves, so it can't shadow the shared Pomerium's
  // aliases nor contend for 8443.
  const container = pomeriumContainer(networkName, opts.configFile, opts.env ?? {}, lines)
    .withWaitStrategy(Wait.forLogMessage(opts.errorPattern))
    .withStartupTimeout(CONFIG_ERROR_TIMEOUT_MS);

  // Either outcome is valid for a fatal-config container: start() resolves if
  // the error line is seen before exit, or rejects if the log stream ends
  // first. Capture lines regardless and stop the container if it lingered.
  try {
    const c = await container.start();
    await c.stop().catch(() => {});
  } catch {
    /* expected: container exits fatally, stream may end before the match */
  }

  // Absorb any log-stream flush still in flight after settle.
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline && !lines.some((l) => opts.errorPattern.test(l))) {
    await sleep(100);
  }
  return lines;
}
