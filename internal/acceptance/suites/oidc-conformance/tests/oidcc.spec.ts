// Runs the OpenID Foundation conformance plans against Pomerium's OIDC bridge,
// one Playwright test per conformance test module. Each test gets a fresh
// browser context, i.e. no Pomerium or Keycloak session carried over from
// earlier modules, which is what the suite assumes.

import { expect, test } from "@playwright/test";
import { logDetailURL } from "../lib/conformance-api.js";
import { getPlan } from "../lib/plans.js";
import { recordOutcome } from "../lib/report.js";
import { describeOutcome, runModule, type ModuleOutcome } from "../lib/run-module.js";
import { ACCEPTED_WARNINGS, PLANS, SKIPPED_MODULES } from "../fixtures/plans.js";

const MODULE_TIMEOUT_MS = 180_000;

for (const spec of PLANS) {
  test.describe(spec.planName, () => {
    for (const moduleName of spec.modules) {
      test(moduleName, async ({ page }, testInfo) => {
        test.setTimeout(MODULE_TIMEOUT_MS + 30_000);
        const plan = getPlan(spec.planName);
        const mod = plan.modules.find((m) => m.testModule === moduleName)!;
        const outcome = await runModule(page, plan.id, mod, MODULE_TIMEOUT_MS);
        recordOutcome(spec.planName, outcome);

        await testInfo.attach("conformance-outcome.json", {
          body: JSON.stringify({ ...outcome, log: logDetailURL(outcome.testId) }, null, 2),
          contentType: "application/json",
        });

        const detail = [`log: ${logDetailURL(outcome.testId)}`, ...describeOutcome(outcome)].join(
          "\n  ",
        );
        expect(acceptable(moduleName, outcome), `${moduleName} → ${outcome.result}\n  ${detail}`).toBe(
          true,
        );
      });
    }
  });
}

function acceptable(moduleName: string, o: ModuleOutcome): boolean {
  if (o.problems.length > 0) return false;
  if (moduleName in SKIPPED_MODULES) return o.result === "SKIPPED";
  if (o.result === "PASSED" || o.result === "REVIEW") return true;
  return (
    o.result === "WARNING" &&
    o.findings.every((f) => f.result === "WARNING" && (f.src ?? "") in ACCEPTED_WARNINGS)
  );
}
