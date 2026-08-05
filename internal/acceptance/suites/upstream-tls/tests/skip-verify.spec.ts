/**
 * Upstream TLS: tls_skip_verify.
 * Test plan: Core.Upstream TLS (disable upstream cert verification).
 *
 * The skip-verify routes target the SNI upstream with NO custom CA and no name
 * override, so the served cert is BOTH untrusted (private CA vs system roots)
 * AND wrong-named (decoy SAN vs the `to` host). With verification on (default)
 * the page fails to load (503); with tls_skip_verify: true Pomerium accepts it
 * anyway - and skip wins even over a (wrong) tls_custom_ca.
 */

import { expect, test } from "@playwright/test";
import { expectHandshake503, gotoEcho } from "../helpers/routes.js";
import { SNI_UPSTREAM_HOST } from "../setup/constants.js";

test.describe("Upstream TLS: skip verify", () => {
  test("default (verify on): untrusted cert + name mismatch is rejected (503)", async ({ page }) => {
    await expectHandshake503(page, "skipVerifyOff");
  });

  test("tls_skip_verify: true accepts the untrusted cert + name mismatch (200)", async ({ page }) => {
    const echo = await gotoEcho(page, "skipVerifyOn");
    // No name override, so the default SNI is the `to` host itself.
    expect(echo.tls.servername).toBe(SNI_UPSTREAM_HOST);
  });

  test("tls_skip_verify overrides a (wrong) tls_custom_ca (200)", async ({ page }) => {
    await gotoEcho(page, "skipVerifyWins");
  });
});
