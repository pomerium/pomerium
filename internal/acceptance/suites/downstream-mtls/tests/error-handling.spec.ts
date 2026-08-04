/**
 * Group A - error handling & no IdP redirect.
 * Test plan: Client Certificates (mTLS), TC-CC-01..04.
 *
 * Uses the base configuration (auth-requiring route policy) so "no IdP
 * redirect on certificate failure" is meaningful: without downstream mTLS the
 * same request WOULD redirect into the login flow (proven by TC-CC-03).
 */

import { test, expect } from "@playwright/test";
import {
  expectDenied495,
  expectLoginRedirect,
  waitForLogLine,
  withCert,
} from "../helpers/api.js";
import { startPomerium, type StartedPomerium } from "../setup/containers.js";
import { baseConfigFile, generateConfig } from "../setup/pomerium-config.js";

test.describe("Group A: error handling (downstream mTLS enabled, base config)", () => {
  let pomerium: StartedPomerium;

  test.beforeAll(async () => {
    pomerium = await startPomerium({ configFile: baseConfigFile() });
  });
  test.afterAll(async () => {
    await pomerium.stop();
  });

  test("TC-CC-01: untrusted client certificate -> 495, no IdP redirect", async () => {
    await withCert("wrong-ca", async (ctx) => {
      const res = await expectDenied495(ctx);
      expect(await res.text()).toContain("a valid client certificate is required");
    });
  });

  test("TC-CC-02: declined client certificate (none presented) -> 495, no IdP redirect", async () => {
    await withCert(null, async (ctx) => {
      const res = await expectDenied495(ctx);
      expect(await res.text()).toContain("a valid client certificate is required");
    });
  });

  test("TC-CC-04: 'no certificate' and 'invalid certificate' are distinct deny reasons", async () => {
    // The authorize service logs the denial reason; the two conditions must
    // surface differently: client-certificate-required (nothing presented)
    // vs invalid-client-certificate (presented but untrusted).
    pomerium.clearLogs();
    await withCert(null, async (ctx) => {
      await expectDenied495(ctx);
      await waitForLogLine(pomerium.logs, /client-certificate-required/);
      expect(pomerium.logs().join("\n")).not.toMatch(/invalid-client-certificate/);
    });

    pomerium.clearLogs();
    await withCert("wrong-ca", async (ctx) => {
      await expectDenied495(ctx);
      await waitForLogLine(pomerium.logs, /invalid-client-certificate/);
      expect(pomerium.logs().join("\n")).not.toMatch(/client-certificate-required/);
    });
  });
});

test.describe("Group A: mTLS disabled", () => {
  let pomerium: StartedPomerium;

  test.beforeAll(async () => {
    pomerium = await startPomerium({
      configFile: generateConfig({ name: "no-mtls", downstreamMtls: null }),
    });
  });
  test.afterAll(async () => {
    await pomerium.stop();
  });

  test("TC-CC-03: no client-certificate mention; normal auth flow proceeds", async () => {
    await withCert(null, async (ctx) => {
      // The request enters the normal login flow instead of failing with 495.
      const res = await expectLoginRedirect(ctx);
      expect((await res.text()).toLowerCase()).not.toContain("client certificate");
    });
  });
});
