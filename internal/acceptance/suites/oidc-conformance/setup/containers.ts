// testcontainers orchestration for the OIDC conformance e2e stack.
//
//   browser ──▶ conformance.localhost.pomerium.io:8443 ─(Pomerium route)─▶ conformance-server:8080
//      │                                                                       │ back-channel:
//      └────▶ authenticate.localhost.pomerium.io:8443 (OIDC bridge OP) ◀───────┘ token/userinfo/jwks
//                  │
//                  └──▶ keycloak.localhost.pomerium.io:8080 (Pomerium's IdP)
//
// Every *.localhost.pomerium.io name is also a Docker network alias, so URLs are
// byte-identical on the host and inside the network. The conformance server's
// REST API is additionally published on 127.0.0.1:18080 for the runner.

import * as path from "node:path";
import {
  GenericContainer,
  Network,
  Wait,
  type StartedNetwork,
  type StartedTestContainer,
} from "testcontainers";
import { ensureCerts } from "./certs.js";
import { CONFORMANCE_API_PORT, CONFORMANCE_BASE_URL } from "./constants.js";

const SUITE_DIR = path.resolve(__dirname, "..");
const ACCEPTANCE_DIR = path.resolve(SUITE_DIR, "..", "..");

const KEYCLOAK_IMPORT_DIR = path.join(ACCEPTANCE_DIR, "keycloak");
const POMERIUM_CONFIG = path.join(SUITE_DIR, "pomerium", "config.yaml");

const KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.5.2";
const MONGO_IMAGE = "mongo:6.0.13";
export const CONFORMANCE_IMAGE =
  process.env.CONFORMANCE_IMAGE ||
  "registry.gitlab.com/openid/conformance-suite:release-v5.3.2";
// Built from this source tree by the Makefile; the bridge is not in any
// published image yet.
const POMERIUM_IMAGE = process.env.POMERIUM_IMAGE || "pomerium-oidc-conformance:local";

const STARTUP_TIMEOUT_MS = 300_000;

/** Lets `make down` find containers left behind by `make test-keep`. */
const STACK_LABEL = { "io.pomerium.e2e": "oidc-conformance" };
const LOGS = !!process.env.OIDC_CONFORMANCE_LOGS;

let started: { network: StartedNetwork; containers: StartedTestContainer[] } | undefined;

function withLogs(c: GenericContainer, prefix: string): GenericContainer {
  c.withLabels(STACK_LABEL);
  if (!LOGS) return c;
  return c.withLogConsumer((stream) => {
    stream.on("data", (line: string) => process.stdout.write(`[${prefix}] ${line}`));
  });
}

export async function startStack(): Promise<void> {
  if (started) return;

  const certsDir = ensureCerts();
  const network = await new Network().start();
  const launched: StartedTestContainer[] = [];
  const launch = async (c: GenericContainer, prefix: string) => {
    const s = await withLogs(c, prefix).start();
    launched.push(s);
    return s;
  };

  try {
    // allSettled, not all: a fast failure must not race the cleanup below
    // against containers that are still starting.
    const results = await Promise.allSettled([
      launch(
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
      ),
      (async () => {
        await launch(
          new GenericContainer(MONGO_IMAGE)
            .withNetwork(network)
            .withNetworkAliases("conformance-mongo")
            .withWaitStrategy(Wait.forLogMessage(/Waiting for connections/))
            .withStartupTimeout(STARTUP_TIMEOUT_MS),
          "mongo",
        );
        return launch(
          new GenericContainer(CONFORMANCE_IMAGE)
            .withNetwork(network)
            .withNetworkAliases("conformance-server")
            .withExposedPorts({ container: 8080, host: CONFORMANCE_API_PORT })
            .withEnvironment({
              BASE_URL: CONFORMANCE_BASE_URL,
              BASE_MTLS_URL: CONFORMANCE_BASE_URL,
              MONGODB_HOST: "conformance-mongo",
              // "dev" disables the suite's own login, so the API needs no token.
              SPRING_PROFILES_ACTIVE: "dev",
              // Spring refuses to start with empty OAuth client registrations
              // for the suite's own (unused) login providers.
              OIDC_GOOGLE_CLIENTID: "unused",
              OIDC_GOOGLE_SECRET: "unused",
              OIDC_GITLAB_CLIENTID: "unused",
              OIDC_GITLAB_SECRET: "unused",
            })
            .withWaitStrategy(
              Wait.forHttp("/api/plan?length=1", 8080)
                // The suite rejects requests that did not arrive over https.
                .withHeaders({ "X-Forwarded-Proto": "https" })
                .forStatusCode(200),
            )
            .withStartupTimeout(STARTUP_TIMEOUT_MS),
          "conformance",
        );
      })(),
      launch(
        new GenericContainer(POMERIUM_IMAGE)
          .withNetwork(network)
          .withNetworkAliases(
            "authenticate.localhost.pomerium.io",
            "conformance.localhost.pomerium.io",
          )
          .withExposedPorts({ container: 8443, host: 8443 })
          .withBindMounts([
            { source: POMERIUM_CONFIG, target: "/pomerium/config.yaml", mode: "ro" },
            { source: certsDir, target: "/certs", mode: "ro" },
          ])
          .withWaitStrategy(
            Wait.forHttp("/healthz", 8443).usingTls().allowInsecure().forStatusCode(200),
          )
          .withStartupTimeout(STARTUP_TIMEOUT_MS),
        "pomerium",
      ),
    ]);
    const failed = results.find((r) => r.status === "rejected");
    if (failed) throw failed.reason;
    started = { network, containers: launched };
  } catch (err) {
    await Promise.all(launched.map((c) => c.stop().catch(() => {})));
    await network.stop().catch(() => {});
    throw err;
  }
}

export async function stopStack(): Promise<void> {
  const s = started;
  started = undefined;
  if (!s) return;
  await Promise.all(s.containers.map((c) => c.stop().catch(() => {})));
  await s.network.stop().catch(() => {});
}
