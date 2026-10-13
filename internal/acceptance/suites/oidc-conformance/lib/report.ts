// Accumulates module outcomes into a single human-readable report,
// oidc-conformance-report.md in the suite directory. (Not under test-results/,
// which Playwright wipes at the start of a run.)

import { appendFileSync, existsSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { logDetailURL } from "./conformance-api.js";
import { describeOutcome, type ModuleOutcome } from "./run-module.js";

export const REPORT_FILE = path.resolve(__dirname, "..", "oidc-conformance-report.md");

export function resetReport(): void {
  writeFileSync(
    REPORT_FILE,
    "# OIDC conformance results\n\n| plan | module | result | findings |\n|---|---|---|---|\n",
  );
}

export function recordOutcome(planName: string, o: ModuleOutcome): void {
  if (!existsSync(REPORT_FILE)) resetReport();
  const findings = describeOutcome(o)
    .map((s) => s.replaceAll("|", "\\|").replaceAll("\n", " "))
    .join("<br>");
  appendFileSync(
    REPORT_FILE,
    `| ${planName} | [${o.testModule}](${logDetailURL(o.testId)}) | ${o.result} | ${findings} |\n`,
  );
}
