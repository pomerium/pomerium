/**
 * Group E - Subject Alternative Name matching.
 * Test plan: Client Certificates (mTLS), TC-CC-15.
 *
 * One configuration carries a matcher per SAN type; a certificate satisfying
 * AT LEAST ONE matcher is allowed. Each SAN-variant fixture cert carries
 * exactly one SAN type, so a pass isolates that type's matcher; the mismatch
 * cert (and the trusted-but-unmatched client-valid cert) prove rejection.
 */

import { test } from "@playwright/test";
import { apiContext, expectDenied495, expectUpstreamReached } from "../helpers/api.js";
import type { ClientCertType } from "../helpers/mtls.js";
import { startPomerium, type StartedPomerium } from "../setup/containers.js";
import { CONTAINER_CERTS, generateConfig } from "../setup/pomerium-config.js";

test.describe("Group E: match_subject_alt_names", () => {
  let pomerium: StartedPomerium;

  test.beforeAll(async () => {
    pomerium = await startPomerium({
      configFile: generateConfig({
        name: "san-matching",
        downstreamMtls: {
          ca_file: CONTAINER_CERTS.rootCA,
          match_subject_alt_names: [
            { dns: "client\\.san-test\\.example" },
            { email: "san-user@san-test\\.example" },
            { ip_address: "10\\.99\\.1\\.1" },
            { uri: "spiffe://san-test\\.example/.*" },
          ],
        },
        route: { publicAccess: true },
      }),
    });
  });
  test.afterAll(async () => {
    await pomerium.stop();
  });

  const matching: Array<{ san: string; cert: ClientCertType }> = [
    { san: "dns", cert: "san-dns" },
    { san: "email", cert: "san-email" },
    { san: "ip_address", cert: "san-ip" },
    { san: "uri", cert: "san-uri" },
  ];

  for (const { san, cert } of matching) {
    test(`TC-CC-15: ${san} matcher - certificate with matching SAN is allowed`, async () => {
      const ctx = await apiContext(cert);
      try {
        await expectUpstreamReached(ctx);
      } finally {
        await ctx.dispose();
      }
    });
  }

  test("TC-CC-15: certificate with non-matching SANs is rejected", async () => {
    const ctx = await apiContext("san-mismatch");
    try {
      await expectDenied495(ctx);
    } finally {
      await ctx.dispose();
    }
  });

  test("TC-CC-15: trusted certificate without any matching SAN is rejected", async () => {
    // client-valid is signed by the trusted CA but its SANs
    // (alice.company.com / alice@company.com) match no configured pattern.
    const ctx = await apiContext("valid");
    try {
      await expectDenied495(ctx);
    } finally {
      await ctx.dispose();
    }
  });
});
