// Playwright global setup: boot the config-invariant services (network,
// Keycloak, upstream, Jaeger) once before any test. Pomerium itself is started
// per test via startPomerium, because nearly every observability case needs
// its own logging/metrics/tracing configuration.

import { startBaseStack } from "./containers.js";
import {
  AUTHENTICATE_URL,
  JAEGER_QUERY_URL,
  KEYCLOAK_REALM_URL,
  METRICS_URL,
  VERIFY_URL,
} from "./constants.js";

export default async function globalSetup(): Promise<void> {
  console.log("\n=== Pomerium observability e2e — booting base stack (testcontainers) ===");
  await startBaseStack();

  console.log(`  Protected route:  ${VERIFY_URL}`);
  console.log(`  Authenticate:     ${AUTHENTICATE_URL}`);
  console.log(`  Keycloak realm:   ${KEYCLOAK_REALM_URL}`);
  console.log(`  Metrics listener: ${METRICS_URL} (when metrics_address is configured)`);
  console.log(`  Jaeger UI/API:    ${JAEGER_QUERY_URL}`);
  console.log("=== base stack ready (Pomerium boots per test) ===\n");
}
