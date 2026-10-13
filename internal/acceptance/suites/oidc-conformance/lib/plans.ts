// Creates every conformance plan once (in global setup) and hands the plan IDs
// to the test workers through the environment, so a failing module does not
// cause a worker restart to create a fresh plan.

import { createPlan, type Plan } from "./conformance-api.js";
import { PLANS } from "../fixtures/plans.js";
import { ALIAS, CLIENT_ID, CLIENT_SECRET, DISCOVERY_URL } from "../setup/constants.js";

const ENV_KEY = "OIDC_CONFORMANCE_PLANS";

const planConfig = {
  alias: ALIAS,
  description: "Pomerium OIDC bridge",
  server: { discoveryUrl: DISCOVERY_URL },
  client: { client_id: CLIENT_ID, client_secret: CLIENT_SECRET },
  // The suite serves one callback per alias, so the second client (used only
  // by the refresh token test) has to be the same one.
  client2: { client_id: CLIENT_ID, client_secret: CLIENT_SECRET },
  client_secret_post: { client_id: CLIENT_ID, client_secret: CLIENT_SECRET },
};

export async function createPlans(): Promise<void> {
  const created: Record<string, Plan> = {};
  for (const spec of PLANS) {
    const plan = await createPlan(spec.planName, planConfig, spec.variant);
    // A newer suite release may add or drop modules; fail loudly rather than
    // silently skipping them.
    const got = plan.modules.map((m) => m.testModule).join(",");
    if (got !== spec.modules.join(",")) {
      throw new Error(
        `${spec.planName}: module list changed; update fixtures/plans.ts.\n  got:  ${got}`,
      );
    }
    created[spec.planName] = plan;
  }
  process.env[ENV_KEY] = JSON.stringify(created);
}

export function getPlan(planName: string): Plan {
  const plans = JSON.parse(process.env[ENV_KEY] ?? "{}") as Record<string, Plan>;
  const plan = plans[planName];
  if (!plan) throw new Error(`plan ${planName} was not created in global setup`);
  return plan;
}
