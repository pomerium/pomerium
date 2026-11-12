// Playwright global teardown: stop the base stack. Per-test Pomerium
// containers are stopped by their tests (and by the testcontainers reaper as
// a fallback).

import { stopBaseStack } from "./containers.js";

export default async function globalTeardown(): Promise<void> {
  console.log("\n=== Pomerium observability e2e — stopping base stack ===");
  await stopBaseStack();
}
