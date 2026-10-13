// Playwright global teardown: stop the container stack (unless asked to keep
// it, so the suite's log viewer stays available for inspection).

import { stopStack } from "./containers.js";

export default async function globalTeardown(): Promise<void> {
  if (process.env.OIDC_CONFORMANCE_KEEP) {
    console.log("\n=== OIDC_CONFORMANCE_KEEP set — leaving containers running ===");
    return;
  }
  console.log("\n=== OIDC conformance e2e — stopping containers ===");
  await stopStack();
}
