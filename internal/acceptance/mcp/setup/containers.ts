// testcontainers orchestration for the MCP e2e stack.
//
// Topology (see README): one Docker network on which every service is reachable
// by a *.localhost.pomerium.io alias that ALSO resolves to 127.0.0.1 on the host.
// Ports are fixed and identical on host and container so the OIDC issuer URL is
// byte-identical from the browser (front-channel) and from inside Pomerium
// (back-channel).
//
//   keycloak.localhost.pomerium.io   HTTP  8080  (reuses ../keycloak realm import)
//   mcp-upstream                     HTTP  8080  (node:22 + ./upstream, mounted)
//   mcp./authenticate.localhost...   HTTPS 8443  (pomerium/pomerium:main)

import * as path from "node:path";
import {
  GenericContainer,
  Network,
  PullPolicy,
  Wait,
  type StartedTestContainer,
  type StartedNetwork,
} from "testcontainers";
import { ensureCerts, type CertPaths } from "./certs.js";

const SETUP_DIR = __dirname;
const MCP_DIR = path.resolve(SETUP_DIR, "..");
const ACCEPTANCE_DIR = path.resolve(MCP_DIR, "..");

const KEYCLOAK_IMPORT_DIR = path.join(ACCEPTANCE_DIR, "keycloak");
const POMERIUM_CONFIG = path.join(MCP_DIR, "pomerium", "config.yaml");
const UPSTREAM_DIR = path.join(MCP_DIR, "upstream");

const KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.5.2";
const NODE_IMAGE = "node:22-alpine";
const POMERIUM_IMAGE = process.env.POMERIUM_IMAGE || "pomerium/pomerium:main";

// testcontainers reuses an already-present local image and never re-pulls a
// mutable tag on its own. That silently pins the suite to a stale `:main` (a
// two-month-old cached image once left `mcp` defaulting off and 404'd every
// route), so force a fresh pull whenever the image is a moving tag. A pinned
// version/digest override is immutable, so leave it on the default policy and
// skip the needless network round-trip.
const POMERIUM_MUTABLE_TAG = /:(main|latest)$/.test(POMERIUM_IMAGE) || !POMERIUM_IMAGE.includes(":");

const STARTUP_TIMEOUT_MS = 240_000;
const LOGS = !!process.env.MCP_E2E_LOGS;

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

    // --- Upstream MCP server -----------------------------------------------
    // Source is bind-mounted read-write; node_modules lives on a tmpfs so the
    // host working tree is not polluted with the installed dependency tree (a
    // read-only bind cannot host the nested tmpfs mountpoint).
    const upstream = await withLogs(
      new GenericContainer(NODE_IMAGE)
        .withNetwork(network)
        .withNetworkAliases("mcp-upstream")
        .withWorkingDir("/app")
        .withBindMounts([{ source: UPSTREAM_DIR, target: "/app", mode: "rw" }])
        .withTmpFs({ "/app/node_modules": "rw" })
        .withEnvironment({ PORT: "8080" })
        .withCommand(["sh", "-c", "npm ci --silent --no-audit --no-fund && node server.mjs"])
        .withWaitStrategy(Wait.forLogMessage(/listening on/))
        .withStartupTimeout(STARTUP_TIMEOUT_MS),
      "upstream",
    ).start();
    launched.push(upstream);

    // --- Pomerium (official image, all-in-one) -----------------------------
    const pomeriumImage = new GenericContainer(POMERIUM_IMAGE);
    if (POMERIUM_MUTABLE_TAG) {
      pomeriumImage.withPullPolicy(PullPolicy.alwaysPull());
    }
    const pomerium = await withLogs(
      pomeriumImage
        .withNetwork(network)
        .withNetworkAliases(
          "authenticate.localhost.pomerium.io",
          "mcp.localhost.pomerium.io",
          "mcp-filtered.localhost.pomerium.io",
        )
        .withExposedPorts({ container: 8443, host: 8443 })
        .withBindMounts([
          { source: POMERIUM_CONFIG, target: "/pomerium/config.yaml", mode: "ro" },
          { source: certs.certsDir, target: "/certs", mode: "ro" },
        ])
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
    // Clean up any containers that did start so a partial failure does not leak
    // them (and their fixed host ports).
    for (const container of launched.reverse()) {
      await container.stop().catch(() => {});
    }
    await network.stop().catch(() => {});
    throw err;
  }
}

export async function stopStack(): Promise<void> {
  const s = started;
  started = undefined;
  if (!s) return;
  // Stop the containers concurrently; the network can only be removed once they
  // have all detached from it.
  await Promise.all([
    s.pomerium.stop().catch(() => {}),
    s.upstream.stop().catch(() => {}),
    s.keycloak.stop().catch(() => {}),
  ]);
  await s.network.stop().catch(() => {});
}
