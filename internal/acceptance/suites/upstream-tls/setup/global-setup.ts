// Playwright global setup: boot the whole stack once before any test — network,
// Keycloak, the verify control upstream, the Node TLS/mTLS echo upstreams, and
// the single shared Pomerium (all behavior routes live in one config). The
// setup project (tests/auth.setup.ts) then logs in against it and saves the
// session; every behavior spec reuses that session via storageState.

import { mkdirSync } from "node:fs";
import type { FullConfig } from "@playwright/test";
import { startBaseStack, startPomerium } from "./containers.js";
import { AUTH_DIR, AUTHENTICATE_URL, KEYCLOAK_REALM_URL } from "./constants.js";
import { mainConfigFile } from "./pomerium-config.js";

export default async function globalSetup(_config: FullConfig): Promise<void> {
  console.log("\n=== Pomerium upstream TLS/mTLS e2e — booting stack (testcontainers) ===");
  mkdirSync(AUTH_DIR, { recursive: true });
  await startBaseStack();
  await startPomerium({ configFile: mainConfigFile() });
  console.log(`  Authenticate:   ${AUTHENTICATE_URL}`);
  console.log(`  Keycloak realm: ${KEYCLOAK_REALM_URL}`);
  console.log("  Upstreams:      upstream (verify), upstream-tls, upstream-mtls, upstream-sni, upstream-reneg");
  console.log("=== stack ready (Pomerium serving :8443; login via setup project) ===\n");
}
