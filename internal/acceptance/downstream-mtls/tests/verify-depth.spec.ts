/**
 * Group F - max_verify_depth.
 * Test plan: Client Certificates (mTLS), TC-CC-16.
 *
 * Trust anchor is the ROOT CA only. Depth counts chain certificates excluding
 * the trust anchor: client-valid verifies at depth 1, the intermediate-signed
 * client-chain leaf needs depth 2. Per config/mtls.go, 0 means "no maximum".
 */

import { test, type APIRequestContext } from "@playwright/test";
import { apiContext, expectDenied495, expectUpstreamReached } from "../helpers/api.js";
import { startPomerium, type PomeriumOptions } from "../setup/containers.js";
import { CONTAINER_CERTS, generateConfig } from "../setup/pomerium-config.js";

interface DepthCase {
  id: string;
  title: string;
  opts: PomeriumOptions;
  directLeafAllowed: boolean; // client-valid (depth 1)
  chainLeafAllowed: boolean; // client-chain via intermediate (depth 2)
}

function config(name: string, maxVerifyDepth?: number): string {
  return generateConfig({
    name,
    downstreamMtls: {
      ca_file: CONTAINER_CERTS.rootCA,
      ...(maxVerifyDepth !== undefined ? { max_verify_depth: maxVerifyDepth } : {}),
    },
    route: { publicAccess: true },
  });
}

const cases: DepthCase[] = [
  {
    id: "TC-CC-16a",
    title: "default (1): only leaves signed directly by the CA verify",
    opts: { configFile: config("depth-default") },
    directLeafAllowed: true,
    chainLeafAllowed: false,
  },
  {
    id: "TC-CC-16b",
    title: "max_verify_depth: 2 allows the intermediate chain",
    opts: { configFile: config("depth-2", 2) },
    directLeafAllowed: true,
    chainLeafAllowed: true,
  },
  {
    id: "TC-CC-16c",
    title: "max_verify_depth: 3 allows the intermediate chain",
    opts: { configFile: config("depth-3", 3) },
    directLeafAllowed: true,
    chainLeafAllowed: true,
  },
  {
    id: "TC-CC-16d",
    title: "max_verify_depth: 0 means no maximum",
    opts: { configFile: config("depth-0", 0) },
    directLeafAllowed: true,
    chainLeafAllowed: true,
  },
  {
    id: "TC-CC-16e",
    title: "DOWNSTREAM_MTLS_MAX_VERIFY_DEPTH environment variable",
    opts: {
      configFile: config("depth-env"),
      env: { DOWNSTREAM_MTLS_MAX_VERIFY_DEPTH: "2" },
    },
    directLeafAllowed: true,
    chainLeafAllowed: true,
  },
];

async function check(cert: "valid" | "chain", allowed: boolean): Promise<void> {
  const ctx: APIRequestContext = await apiContext(cert);
  try {
    if (allowed) {
      await expectUpstreamReached(ctx);
    } else {
      await expectDenied495(ctx);
    }
  } finally {
    await ctx.dispose();
  }
}

test.describe("Group F: max_verify_depth", () => {
  for (const c of cases) {
    test(`${c.id}: ${c.title}`, async () => {
      const pomerium = await startPomerium(c.opts);
      try {
        await check("valid", c.directLeafAllowed);
        await check("chain", c.chainLeafAllowed);
      } finally {
        await pomerium.stop();
      }
    });
  }
});
