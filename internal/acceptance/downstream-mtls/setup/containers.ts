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

import * as path from "node:path";
import {
  GenericContainer,
  Network,
  Wait,
  type StartedTestContainer,
  type StartedNetwork,
} from "testcontainers";
import { ensureCerts, type CertPaths } from "./certs.js";

const SETUP_DIR = __dirname;
const SUITE_DIR = path.resolve(SETUP_DIR, "..");
const ACCEPTANCE_DIR = path.resolve(SUITE_DIR, "..");

const KEYCLOAK_IMPORT_DIR = path.join(ACCEPTANCE_DIR, "keycloak");
const POMERIUM_CONFIG = path.join(SUITE_DIR, "pomerium", "config.yaml");

const KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.5.2";
const UPSTREAM_IMAGE = "traefik/whoami:v1.11";
const POMERIUM_IMAGE = process.env.POMERIUM_IMAGE || "pomerium/pomerium:main";

const STARTUP_TIMEOUT_MS = 240_000;
const LOGS = !!process.env.MTLS_E2E_LOGS;

export interface Stack {
  network: StartedNetwork;
  keycloak: StartedTestContainer;
  upstream: StartedTestContainer;
  pomerium: StartedTestContainer;
  certs: CertPaths;
}

let started: Stack | undefined;

function logConsumer(prefix: string) {
  return (stream: { on(event: "data", cb: (line: string) => void): void }) => {
    stream.on("data", (line) => process.stdout.write(`[${prefix}] ${line}`));
  };
}

function withLogs(c: GenericContainer, prefix: string): GenericContainer {
  return LOGS ? c.withLogConsumer(logConsumer(prefix)) : c;
}

export async function startStack(): Promise<Stack> {
  if (started) return started;

  const certs = ensureCerts();
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
    // identity headers assertable. Built FROM scratch, so wait on its log.
    const upstream = await withLogs(
      new GenericContainer(UPSTREAM_IMAGE)
        .withNetwork(network)
        .withNetworkAliases("upstream")
        .withWaitStrategy(Wait.forLogMessage(/Starting up on port/))
        .withStartupTimeout(STARTUP_TIMEOUT_MS),
      "upstream",
    ).start();
    launched.push(upstream);

    // --- Pomerium (official image, all-in-one) -----------------------------
    const pomerium = await withLogs(
      new GenericContainer(POMERIUM_IMAGE)
        .withNetwork(network)
        .withNetworkAliases(
          "authenticate.localhost.pomerium.io",
          "mtls.localhost.pomerium.io",
        )
        .withExposedPorts({ container: 8443, host: 8443 })
        .withBindMounts([
          { source: POMERIUM_CONFIG, target: "/pomerium/config.yaml", mode: "ro" },
          { source: certs.certsDir, target: "/certs", mode: "ro" },
        ])
        // /healthz is a control-plane route exempt from the mTLS default deny
        // (enforcement: policy_with_default_deny), so this probe needs no
        // client certificate. A future reject_connection config would break
        // it - switch to a log-based wait for that variant.
        .withWaitStrategy(
          Wait.forHttp("/healthz", 8443).usingTls().allowInsecure().forStatusCode(200),
        )
        .withStartupTimeout(STARTUP_TIMEOUT_MS),
      "pomerium",
    ).start();
    launched.push(pomerium);

    started = { network, keycloak, upstream, pomerium, certs };
    return started;
  } catch (err) {
    await Promise.allSettled(launched.reverse().map((c) => c.stop()));
    await network.stop().catch(() => {});
    throw err;
  }
}

export async function stopStack(): Promise<void> {
  if (!started) return;
  const { network, keycloak, upstream, pomerium } = started;
  started = undefined;
  await Promise.allSettled([pomerium.stop(), upstream.stop(), keycloak.stop()]);
  await network.stop().catch(() => {});
}
