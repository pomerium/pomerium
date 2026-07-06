// testcontainers orchestration for the downstream mTLS e2e stack.
// Modeled on internal/acceptance/mcp/setup/containers.ts.
//
// Topology: one Docker network on which every service is reachable by a
// *.localhost.pomerium.io alias that ALSO resolves to 127.0.0.1 on the host.
// Ports are fixed and identical on host and container so the OIDC issuer URL
// is byte-identical from the browser (front-channel) and from inside Pomerium
// (back-channel).
//
//   keycloak.localhost.pomerium.io        HTTP  8080  (reuses ../keycloak realm import)
//   upstream                              HTTP    80  (traefik/whoami, echoes headers)
//   mtls./authenticate.localhost...io     HTTPS 8443  (official pomerium image)
//
// Lifecycle: the config-INVARIANT services (network, Keycloak, upstream) boot
// once in Playwright's global setup (runner process) and their network name is
// handed to the workers via process.env. Pomerium itself is started PER SPEC
// FILE by the worker (startPomerium below), because most test groups need
// their own downstream_mtls configuration; specs run serially (workers: 1) so
// the fixed 8443 port is never contended.

import * as path from "node:path";
import {
  GenericContainer,
  Network,
  Wait,
  type StartedTestContainer,
  type StartedNetwork,
} from "testcontainers";
import { ensureCerts, type CertPaths } from "./certs.js";
import { waitForTLS } from "../helpers/raw-tls.js";

const SETUP_DIR = __dirname;
const SUITE_DIR = path.resolve(SETUP_DIR, "..");
const ACCEPTANCE_DIR = path.resolve(SUITE_DIR, "..");

const KEYCLOAK_IMPORT_DIR = path.join(ACCEPTANCE_DIR, "keycloak");

const KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.5.2";
const UPSTREAM_IMAGE = "traefik/whoami:v1.11";
const POMERIUM_IMAGE = process.env.POMERIUM_IMAGE || "pomerium/pomerium:main";

const STARTUP_TIMEOUT_MS = 240_000;
// Pomerium boots in ~2s; keep its startup wait WELL below the Playwright test
// timeout (120s) so a failed wait strategy cleans the container up instead of
// being abandoned mid-start (which leaks the fixed 8443 port binding).
const POMERIUM_STARTUP_TIMEOUT_MS = 90_000;
const LOGS = !!process.env.MTLS_E2E_LOGS;

// Env var carrying the shared network name from global setup to the workers.
const NETWORK_ENV = "MTLS_E2E_NETWORK";

export interface BaseStack {
  network: StartedNetwork;
  keycloak: StartedTestContainer;
  upstream: StartedTestContainer;
  certs: CertPaths;
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

/** Boot the config-invariant services. Called from Playwright global setup. */
export async function startBaseStack(): Promise<BaseStack> {
  if (base) return base;

  const certPaths = certs();
  const network = await new Network().start();
  const launched: StartedTestContainer[] = [];

  try {
    // --- Keycloak (IdP) ----------------------------------------------------
    const keycloak = await withLogs(
      new GenericContainer(KEYCLOAK_IMAGE)
        .withNetwork(network)
        .withNetworkAliases("keycloak.localhost.pomerium.io")
        .withExposedPorts({ container: 8080, host: 8080 }, 9000)
        .withEnvironment({
          KC_BOOTSTRAP_ADMIN_USERNAME: "admin",
          KC_BOOTSTRAP_ADMIN_PASSWORD: "admin",
          KC_HTTP_ENABLED: "true",
          KC_HOSTNAME: "keycloak.localhost.pomerium.io",
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
    ).start();
    launched.push(keycloak);

    // --- Upstream echo server ----------------------------------------------
    // whoami echoes the request headers, which makes Pomerium's injected
    // headers assertable. Built FROM scratch, so wait on its log.
    const upstream = await withLogs(
      new GenericContainer(UPSTREAM_IMAGE)
        .withNetwork(network)
        .withNetworkAliases("upstream")
        .withWaitStrategy(Wait.forLogMessage(/Starting up on port/))
        .withStartupTimeout(STARTUP_TIMEOUT_MS),
      "upstream",
    ).start();
    launched.push(upstream);

    // Hand the network to the worker processes (they inherit process.env).
    process.env[NETWORK_ENV] = network.getName();

    base = { network, keycloak, upstream, certs: certPaths };
    return base;
  } catch (err) {
    await Promise.allSettled(launched.reverse().map((c) => c.stop()));
    await network.stop().catch(() => {});
    throw err;
  }
}

/** Stop the config-invariant services. Called from Playwright global teardown. */
export async function stopBaseStack(): Promise<void> {
  if (!base) return;
  const { network, keycloak, upstream } = base;
  base = undefined;
  await Promise.allSettled([upstream.stop(), keycloak.stop()]);
  await network.stop().catch(() => {});
}

export interface PomeriumOptions {
  /** Host path of the config file to mount at /pomerium/config.yaml. */
  configFile: string;
  /** Extra environment variables (e.g. DOWNSTREAM_MTLS_CA_FILE). */
  env?: Record<string, string>;
  /**
   * Readiness gate. "healthz" (default) probes /healthz over TLS without a
   * client certificate - valid for every enforcement mode EXCEPT
   * reject_connection, where the TLS handshake itself requires a trusted
   * client certificate; use "client-cert-tls" there.
   */
  wait?: "healthz" | "client-cert-tls";
}

export interface StartedPomerium {
  container: StartedTestContainer;
  /** Lines captured from the container's stdout/stderr since start. */
  logs(): string[];
  clearLogs(): void;
  stop(): Promise<void>;
}

let currentPomerium: StartedPomerium | undefined;

/**
 * Start a Pomerium container (official image) with the given configuration,
 * bound to host port 8443. At most one instance runs at a time - a previous
 * instance is stopped first. Called from spec files (worker process), which
 * reach the shared network via the name exported by global setup.
 */
export async function startPomerium(opts: PomeriumOptions): Promise<StartedPomerium> {
  const networkName = process.env[NETWORK_ENV] ?? base?.network.getName();
  if (!networkName) {
    throw new Error(
      `${NETWORK_ENV} is not set - the base stack (global setup) must run before startPomerium`,
    );
  }
  if (currentPomerium) {
    await currentPomerium.stop();
  }

  const certPaths = certs();
  const lines: string[] = [];

  let container = new GenericContainer(POMERIUM_IMAGE)
    .withNetworkMode(networkName)
    .withNetworkAliases("authenticate.localhost.pomerium.io", "mtls.localhost.pomerium.io")
    .withExposedPorts({ container: 8443, host: 8443 })
    .withEnvironment(opts.env ?? {})
    .withBindMounts([
      { source: opts.configFile, target: "/pomerium/config.yaml", mode: "ro" },
      { source: certPaths.certsDir, target: "/certs", mode: "ro" },
    ])
    .withLogConsumer((stream) => {
      stream.on("data", (line: string) => {
        lines.push(line);
        if (LOGS) process.stdout.write(`[pomerium] ${line}`);
      });
    })
    .withStartupTimeout(POMERIUM_STARTUP_TIMEOUT_MS);

  // /healthz is a control-plane route exempt from the mTLS default deny, so
  // the default probe needs no client certificate. Under reject_connection
  // every connection needs one, so the container-start wait only gates on
  // first log output (the distroless image has no shell for port checks) and
  // the real readiness gate is the client-cert TLS poll below.
  container =
    opts.wait === "client-cert-tls"
      ? container.withWaitStrategy(Wait.forLogMessage(/./))
      : container.withWaitStrategy(
          Wait.forHttp("/healthz", 8443).usingTls().allowInsecure().forStatusCode(200),
        );

  // Docker can release a stopped container's host-port binding slightly after
  // stop() resolves; with back-to-back variants on the fixed 8443 port that
  // surfaces as "port is already allocated" - retry briefly.
  const startedContainer = await (async () => {
    for (let attempt = 1; ; attempt++) {
      try {
        return await container.start();
      } catch (err) {
        const message = String(err);
        if (attempt >= 10 || !/port is already allocated/.test(message)) throw err;
        await new Promise((r) => setTimeout(r, 1_000));
      }
    }
  })();

  const started: StartedPomerium = {
    container: startedContainer,
    logs: () => [...lines],
    clearLogs: () => {
      lines.length = 0;
    },
    stop: async () => {
      if (currentPomerium === started) currentPomerium = undefined;
      await startedContainer.stop().catch(() => {});
    },
  };
  currentPomerium = started;

  if (opts.wait === "client-cert-tls") {
    try {
      await waitForTLS({
        servername: "mtls.localhost.pomerium.io",
        certPath: path.join(certPaths.mtlsDir, "client-valid.crt"),
        keyPath: path.join(certPaths.mtlsDir, "client-valid.key"),
      });
    } catch (err) {
      await started.stop();
      throw err;
    }
  }

  return started;
}
