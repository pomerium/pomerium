// testcontainers orchestration for the observability e2e stack.
// Modeled on internal/acceptance/suites/downstream-mtls/setup/containers.ts.
//
// Topology: one Docker network on which every service is reachable by a
// *.localhost.pomerium.io alias that ALSO resolves to 127.0.0.1 on the host.
// Ports are fixed and identical on host and container so the OIDC issuer URL
// is byte-identical from the browser (front-channel) and from inside Pomerium
// (back-channel).
//
//   keycloak.localhost.pomerium.io      HTTP  8080   (reuses ../../keycloak realm import)
//   upstream                            HTTP  8000   (pomerium/verify)
//   jaeger                              OTLP  4317/4318 in-network; query API 16686 on the host
//   verify./authenticate.localhost...   HTTPS 8443   (official pomerium image)
//                                       +     9902   (metrics listener, when configured)
//
// Lifecycle: the config-INVARIANT services (network, Keycloak, upstream,
// Jaeger) boot once in Playwright's global setup (runner process) and their
// network name is handed to the workers via process.env. Pomerium itself is
// started PER TEST by the worker (startPomerium below), because nearly every
// case needs its own logging/metrics/tracing configuration; specs run serially
// (workers: 1) so the fixed ports are never contended.

import * as net from "node:net";
import * as path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import {
  GenericContainer,
  Network,
  PullPolicy,
  Wait,
  type StartedTestContainer,
  type StartedNetwork,
} from "testcontainers";
import { ensureCerts } from "./certs.js";
import {
  AUTHENTICATE_HOSTNAME,
  CERTS_DIR,
  JAEGER_ALIAS,
  JAEGER_QUERY_PORT,
  KEYCLOAK_HOSTNAME,
  METRICS_PORT,
  NETWORK_ENV,
  SUITE_DIR,
  VERIFY_HOSTNAME,
} from "./constants.js";

const ACCEPTANCE_DIR = path.resolve(SUITE_DIR, "..", "..");
const KEYCLOAK_IMPORT_DIR = path.join(ACCEPTANCE_DIR, "keycloak");

const KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.5.2";
// Pomerium's own demo upstream. Pinned to the same digest the parent
// acceptance suite uses (internal/acceptance/docker-compose.yml) so both
// suites pull an identical build; override with VERIFY_IMAGE.
const UPSTREAM_IMAGE =
  process.env.VERIFY_IMAGE ||
  "pomerium/verify@sha256:6d9dd40deae8d3ae7517485febf6fd4e7de2692e9dc1a2859c00e3426559af96";
// Jaeger v2 all-in-one: OTLP receivers on 4317 (gRPC) and 4318 (HTTP) are on
// by default, spans are queryable through the classic API on 16686. Pinned by
// DIGEST (the tag names the human-readable version, the digest makes it
// immutable - same posture as the verify image above); override with
// JAEGER_IMAGE. To bump: docker pull the new tag, then record the printed
// digest here.
const JAEGER_IMAGE =
  process.env.JAEGER_IMAGE ||
  "jaegertracing/jaeger:2.20.0@sha256:46a886260e04002d8f45e213fc39063fa11a50446048fdaa64786fc0840cb9f8";
const POMERIUM_IMAGE = process.env.POMERIUM_IMAGE || "pomerium/pomerium:main";

// testcontainers reuses an already-present local image and never re-pulls a
// mutable tag on its own. That silently pins the suite to a stale `:main` (a
// two-month-old cached image once left suites/mcp defaulting `mcp` off and
// 404'ing every route), so force a fresh pull whenever the image is a moving
// tag. A pinned version/digest override is immutable, so leave it on the
// default policy and skip the needless network round-trip.
function isMutableTag(image: string): boolean {
  // A digest pin (@sha256:...) is immutable regardless of any tag.
  if (image.includes("@")) return false;
  const lastComponent = image.slice(image.lastIndexOf("/") + 1);
  const colon = lastComponent.indexOf(":");
  // No tag → Docker defaults to the mutable `:latest`.
  if (colon === -1) return true;
  const tag = lastComponent.slice(colon + 1);
  return tag === "main" || tag === "latest";
}

// One forced pull per process is enough: `alwaysPull` bypasses the local-image
// fast path, so leaving it on would spend a registry round-trip on each of the
// ~20 per-test starts (and burn Docker Hub's anonymous rate limit).
let pomeriumPulled = false;

const STARTUP_TIMEOUT_MS = 240_000;
// Pomerium boots in ~2s, so a long wait here buys nothing and risks blowing the
// Playwright test timeout (120s) mid-start, which would abandon a container
// holding the fixed ports. Keep the per-attempt wait short and bound the total
// by POMERIUM_START_BUDGET_MS instead.
const POMERIUM_WAIT_TIMEOUT_MS = 30_000;
const POMERIUM_START_BUDGET_MS = 75_000;
const LOGS = !!process.env.OBS_E2E_LOGS;

/** Pomerium's startup line; absence means it never finished booting. */
const SERVER_STARTED = '"server started"';

interface BaseStack {
  network: StartedNetwork;
  containers: StartedTestContainer[];
}

let base: BaseStack | undefined;

/**
 * Stream a container's output, optionally into `sink`. Enabled for stdout only
 * under OBS_E2E_LOGS; a sink is always attached when given, since assertions
 * read from it.
 */
function withLogs(c: GenericContainer, prefix: string, sink?: string[]): GenericContainer {
  if (!LOGS && !sink) return c;
  return c.withLogConsumer((stream) => {
    stream.on("data", (line: string) => {
      sink?.push(line);
      if (LOGS) process.stdout.write(`[${prefix}] ${line}`);
    });
  });
}

/** Boot the config-invariant services. Called from Playwright global setup. */
export async function startBaseStack(): Promise<void> {
  if (base) return;

  ensureCerts(); // generate the leaf up front so workers hit the freshness fast path
  const network = await new Network().start();
  const started: StartedTestContainer[] = [];

  try {
    // --- Keycloak (IdP) ----------------------------------------------------
    const keycloakContainer = withLogs(
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

    // --- Upstream (pomerium/verify) ----------------------------------------
    // verify's /json returns the x-pomerium-claim-* headers Pomerium injected
    // plus the parsed identity, which makes injected identity assertable. It
    // has no host-exposed port (it is reached in-network via the "upstream"
    // alias), so gate on its startup log rather than an HTTP probe.
    const upstreamContainer = withLogs(
      new GenericContainer(UPSTREAM_IMAGE)
        .withNetwork(network)
        .withNetworkAliases("upstream")
        .withWaitStrategy(Wait.forLogMessage(/starting http server/))
        .withStartupTimeout(STARTUP_TIMEOUT_MS),
      "upstream",
    );

    // --- Jaeger (OTLP collector + query API) --------------------------------
    // Pomerium reaches the OTLP receivers in-network (jaeger:4317 / :4318), so
    // those ports are not published; only the query API is, on its fixed port,
    // for the tests and for humans debugging a run.
    const jaegerContainer = withLogs(
      new GenericContainer(JAEGER_IMAGE)
        .withNetwork(network)
        .withNetworkAliases(JAEGER_ALIAS)
        .withExposedPorts({ container: JAEGER_QUERY_PORT, host: JAEGER_QUERY_PORT })
        .withWaitStrategy(Wait.forHttp("/api/services", JAEGER_QUERY_PORT).forStatusCode(200))
        .withStartupTimeout(STARTUP_TIMEOUT_MS),
      "jaeger",
    );

    // The services are independent; boot them concurrently (Keycloak dominates
    // the wall time). Whatever started before a failure is stopped below.
    const track = async (c: GenericContainer) => void started.push(await c.start());
    await Promise.all([
      track(keycloakContainer),
      track(upstreamContainer),
      track(jaegerContainer),
    ]);

    // Hand the network to the worker processes (they inherit process.env).
    process.env[NETWORK_ENV] = network.getName();

    base = { network, containers: started };
  } catch (err) {
    await Promise.allSettled(started.map((c) => c.stop()));
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
  /** Extra environment variables (e.g. OTEL_SDK_DISABLED). */
  env?: Record<string, string>;
}

export interface StartedPomerium {
  /** Lines captured from the container's stdout/stderr since start. */
  logs(): string[];
  /** Number of captured lines, without copying the buffer. */
  lineCount(): number;
  clearLogs(): void;
  stop(): Promise<void>;
}

let currentPomerium: StartedPomerium | undefined;

/** True when something is accepting connections on a host port. */
async function portIsBound(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net
      .connect({ host: "127.0.0.1", port })
      .on("connect", () => {
        socket.destroy();
        resolve(true);
      })
      .on("error", () => resolve(false))
      .setTimeout(1_000, () => {
        socket.destroy();
        resolve(false);
      });
  });
}

/**
 * Wait until the fixed host ports are unbound.
 *
 * Docker releases a stopped container's port bindings asynchronously, some way
 * after stop() resolves. Binding them again too early either fails outright
 * ("port is already allocated") or - worse on Docker Desktop - appears to
 * succeed while the forward still points at the dead container, so the new
 * container looks unhealthy. Waiting for the ports as a precondition is what
 * makes the retry below a rare backstop rather than the mechanism.
 */
async function waitForPortsFree(ports: number[], timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const bound = await Promise.all(ports.map(portIsBound));
    if (!bound.some(Boolean)) return;
    if (Date.now() > deadline) return; // let the start attempt surface the problem
    await sleep(250);
  }
}

function pomeriumContainer(opts: PomeriumOptions, sink: string[], publishPorts: boolean): GenericContainer {
  const networkName = process.env[NETWORK_ENV];
  if (!networkName) {
    throw new Error(
      `${NETWORK_ENV} is not set - the base stack (global setup) must run before startPomerium`,
    );
  }

  const container = withLogs(
    new GenericContainer(POMERIUM_IMAGE)
      .withNetworkMode(networkName)
      .withNetworkAliases(AUTHENTICATE_HOSTNAME, VERIFY_HOSTNAME)
      .withEnvironment(opts.env ?? {})
      .withBindMounts([
        { source: opts.configFile, target: "/pomerium/config.yaml", mode: "ro" },
        { source: CERTS_DIR, target: "/certs", mode: "ro" },
      ]),
    "pomerium",
    sink,
  );
  if (publishPorts) {
    // 9902 (metrics_address) is published whatever the config says: whether
    // anything listens there is exactly what the metrics specs assert.
    container.withExposedPorts(
      { container: 8443, host: 8443 },
      { container: METRICS_PORT, host: METRICS_PORT },
    );
  }
  if (isMutableTag(POMERIUM_IMAGE) && !pomeriumPulled) {
    container.withPullPolicy(PullPolicy.alwaysPull());
    pomeriumPulled = true;
  }
  return container;
}

function withLogTail(message: string, lines: string[]): string {
  const tail = lines.slice(-25).map((l) => l.trimEnd()).join("\n");
  return `${message}\n--- pomerium output (last 25 lines) ---\n${tail}`;
}

/**
 * Start a Pomerium container (official image) with the given configuration,
 * bound to host ports 8443 and 9902. At most one instance runs at a time - a
 * previous instance is stopped first. Called from spec files (worker process),
 * which reach the shared network via the name exported by global setup.
 */
export async function startPomerium(opts: PomeriumOptions): Promise<StartedPomerium> {
  if (currentPomerium) {
    await currentPomerium.stop();
  }

  const lines: string[] = [];
  const deadline = Date.now() + POMERIUM_START_BUDGET_MS;
  let startedContainer: StartedTestContainer | undefined;

  for (let attempt = 1; !startedContainer; attempt++) {
    await waitForPortsFree([8443, METRICS_PORT]);
    try {
      startedContainer = await pomeriumContainer(opts, lines, true)
        .withWaitStrategy(
          Wait.forHttp("/healthz", 8443).usingTls().allowInsecure().forStatusCode(200),
        )
        .withStartupTimeout(POMERIUM_WAIT_TIMEOUT_MS)
        .start();
    } catch (err) {
      // Classify by OUR OWN captured output rather than the wait strategy's
      // error text. Output but no "server started" means Pomerium booted and
      // rejected something - retrying would only hide a real config problem,
      // so surface it with the logs. Otherwise the process was fine (or never
      // ran) and the host-side probe is what failed, which a fresh start
      // fixes; testcontainers has already removed the failed container.
      const booted = lines.some((l) => l.includes(SERVER_STARTED));
      const startedAndFailed = lines.length > 0 && !booted;
      if (startedAndFailed || Date.now() > deadline) {
        throw new Error(withLogTail(`pomerium failed to start: ${err}`, lines), { cause: err });
      }
      if (LOGS) process.stdout.write(`[pomerium] start attempt ${attempt} failed, retrying\n`);
      await sleep(1_000);
    }
  }

  const started: StartedPomerium = {
    logs: () => [...lines],
    lineCount: () => lines.length,
    clearLogs: () => {
      lines.length = 0;
    },
    stop: async () => {
      if (currentPomerium === started) currentPomerium = undefined;
      await startedContainer.stop().catch(() => {});
    },
  };
  currentPomerium = started;
  return started;
}

/**
 * Start Pomerium for the duration of one callback and always stop it. Specs
 * use this INSIDE the test body (not beforeAll) so a Playwright retry
 * re-creates the container instead of reusing a torn-down one.
 */
export async function withPomerium<T>(
  opts: PomeriumOptions,
  fn: (pomerium: StartedPomerium) => Promise<T>,
): Promise<T> {
  const pomerium = await startPomerium(opts);
  try {
    return await fn(pomerium);
  } finally {
    await pomerium.stop();
  }
}

/**
 * Assert that a configuration is REJECTED at load: Pomerium must log
 * `errorPattern` and must never reach "server started". Throws (with the
 * container's output) when either expectation fails, so calling this IS the
 * assertion - no follow-up expect needed.
 *
 * No host ports are published: nothing ever connects to this container, and
 * leaving the fixed ports alone keeps it out of the port-release race.
 */
export async function startPomeriumExpectExit(
  opts: PomeriumOptions,
  errorPattern: RegExp,
): Promise<string[]> {
  if (currentPomerium) {
    await currentPomerium.stop();
  }

  const lines: string[] = [];
  try {
    const container = await pomeriumContainer(opts, lines, false)
      .withWaitStrategy(Wait.forLogMessage(errorPattern))
      .withStartupTimeout(POMERIUM_WAIT_TIMEOUT_MS)
      .start();
    await container.stop().catch(() => {});
  } catch {
    // The container exited before the wait strategy settled, or the pattern
    // never appeared. Either way testcontainers tore it down; the assertions
    // below run on whatever output was captured.
  }

  const output = lines.join("\n");
  if (!errorPattern.test(output)) {
    throw new Error(
      withLogTail(`expected pomerium to reject the config with ${errorPattern}`, lines),
    );
  }
  if (lines.some((l) => l.includes(SERVER_STARTED))) {
    throw new Error(
      withLogTail("pomerium started serving despite the invalid config", lines),
    );
  }
  return [...lines];
}
