// Playwright global teardown: stop the shared Pomerium, then the base stack.

import { stopBaseStack, stopCurrentPomerium } from "./containers.js";

export default async function globalTeardown(): Promise<void> {
  console.log("\n=== Pomerium upstream TLS/mTLS e2e — stopping stack ===");
  await stopCurrentPomerium();
  await stopBaseStack();
}
