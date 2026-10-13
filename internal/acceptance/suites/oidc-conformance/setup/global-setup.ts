// Playwright global setup: boot the whole container stack once before any test.

import type { FullConfig } from "@playwright/test";
import { createPlans } from "../lib/plans.js";
import { resetReport, REPORT_FILE } from "../lib/report.js";
import { CONFORMANCE_API_URL, CONFORMANCE_BASE_URL, ISSUER } from "./constants.js";
import { CONFORMANCE_IMAGE, startStack } from "./containers.js";

export default async function globalSetup(_config: FullConfig): Promise<void> {
  console.log("\n=== OIDC conformance e2e — booting containers (testcontainers) ===");
  await startStack();
  await createPlans();
  resetReport();
  console.log(`  OP (issuer):        ${ISSUER}`);
  console.log(`  conformance suite:  ${CONFORMANCE_BASE_URL} (${CONFORMANCE_IMAGE})`);
  console.log(`  suite API / logs:   ${CONFORMANCE_API_URL}`);
  console.log(`  report:             ${REPORT_FILE}`);
  console.log("=== containers ready ===\n");
}
