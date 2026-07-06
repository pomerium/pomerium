// Playwright global teardown: stop the base stack. Per-spec Pomerium
// containers are stopped by their spec files (and by the testcontainers
// reaper as a fallback).

import { stopBaseStack } from "./containers.js";

export default async function globalTeardown(): Promise<void> {
  console.log("\n=== Pomerium downstream mTLS e2e — stopping base stack ===");
  await stopBaseStack();
}
