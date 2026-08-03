// Playwright global setup: boot the config-invariant services (network,
// Keycloak, upstream) once before any test. Pomerium itself is started per
// spec file via startPomerium, because most test groups need their own
// downstream_mtls configuration.

import type { FullConfig } from "@playwright/test";
import { startBaseStack } from "./containers.js";
import { AUTHENTICATE_URL, KEYCLOAK_REALM_URL, MTLS_URL } from "./constants.js";

export default async function globalSetup(_config: FullConfig): Promise<void> {
  console.log("\n=== Pomerium downstream mTLS e2e — booting base stack (testcontainers) ===");
  await startBaseStack();

  console.log(`  mTLS route:      ${MTLS_URL}`);
  console.log(`  Authenticate:    ${AUTHENTICATE_URL}`);
  console.log(`  Keycloak realm:  ${KEYCLOAK_REALM_URL}`);
  console.log("=== base stack ready (Pomerium boots per spec file) ===\n");
}
