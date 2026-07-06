// Playwright global setup: boot the whole container stack once before any test.

import type { FullConfig } from "@playwright/test";
import { startStack } from "./containers.js";
import { AUTHENTICATE_URL, MTLS_URL } from "./constants.js";

export default async function globalSetup(_config: FullConfig): Promise<void> {
  console.log("\n=== Pomerium downstream mTLS e2e — booting containers (testcontainers) ===");
  const stack = await startStack();

  console.log(`  mTLS route:      ${MTLS_URL}`);
  console.log(`  Authenticate:    ${AUTHENTICATE_URL}`);
  console.log("  Keycloak realm:  http://keycloak.localhost.pomerium.io:8080/realms/pomerium-e2e");
  console.log(`  Certificates:    ${stack.certs.certsDir}`);
  console.log("=== containers ready ===\n");
}
