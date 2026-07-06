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
  apiContext,
  expectDenied495,
  getNoRedirect,
  waitForLogLine,
} from "../helpers/api.js";
import { startPomerium, type StartedPomerium } from "../setup/containers.js";
import { BASE_CONFIG_FILE, generateConfig } from "../setup/pomerium-config.js";
import { MTLS_URL } from "../setup/constants.js";

test.describe("Group A: error handling (downstream mTLS enabled, base config)", () => {
  let pomerium: StartedPomerium;

  test.beforeAll(async () => {
    pomerium = await startPomerium({ configFile: BASE_CONFIG_FILE });
  });
  test.afterAll(async () => {
    await pomerium.stop();
  });

  test("TC-CC-01: untrusted client certificate -> 495, no IdP redirect", async () => {
    const ctx = await apiContext("wrong-ca");
    try {
      const res = await expectDenied495(ctx);
      expect(await res.text()).toContain("a valid client certificate is required");
    } finally {
      await ctx.dispose();
    }
  });

  test("TC-CC-02: declined client certificate (none presented) -> 495, no IdP redirect", async () => {
    const ctx = await apiContext(null);
    try {
      const res = await expectDenied495(ctx);
      expect(await res.text()).toContain("a valid client certificate is required");
    } finally {
      await ctx.dispose();
    }
  });

  test("TC-CC-04: 'no certificate' and 'invalid certificate' are distinct deny reasons", async () => {
    // The authorize service logs the denial reason; the two conditions must
    // surface differently: client-certificate-required (nothing presented)
    // vs invalid-client-certificate (presented but untrusted).
    pomerium.clearLogs();
    const noCert = await apiContext(null);
    try {
      await expectDenied495(noCert);
      await waitForLogLine(pomerium.logs, /client-certificate-required/);
      expect(pomerium.logs().join("\n")).not.toMatch(/invalid-client-certificate/);
    } finally {
      await noCert.dispose();
    }

    pomerium.clearLogs();
    const badCert = await apiContext("wrong-ca");
    try {
      await expectDenied495(badCert);
      await waitForLogLine(pomerium.logs, /invalid-client-certificate/);
      expect(pomerium.logs().join("\n")).not.toMatch(/client-certificate-required/);
    } finally {
      await badCert.dispose();
    }
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
    const ctx = await apiContext(null);
    try {
      const res = await getNoRedirect(ctx, MTLS_URL);
      // The request enters the normal login flow instead of failing with 495.
      expect(res.status()).toBe(302);
      const location = res.headers()["location"] ?? "";
      expect(location).toMatch(/authenticate\.localhost\.pomerium\.io|\.pomerium\/sign_in/);
      expect((await res.text()).toLowerCase()).not.toContain("client certificate");
    } finally {
      await ctx.dispose();
    }
  });
});
