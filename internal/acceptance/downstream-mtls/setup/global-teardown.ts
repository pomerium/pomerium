// Playwright global teardown: stop the container stack. Shares module state
// with global-setup via the cached containers.ts module in the same runner
// process.

import { stopStack } from "./containers.js";

export default async function globalTeardown(): Promise<void> {
  console.log("\n=== Pomerium downstream mTLS e2e — stopping containers ===");
  await stopStack();
}
