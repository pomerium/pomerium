/**
 * Upstream TLS: tls_skip_verify.
 * Test plan: Core.Upstream TLS (disable upstream cert verification).
 *
 * The skip-verify routes target the SNI upstream with NO custom CA and no name
 * override, so the served cert is BOTH untrusted (private CA vs system roots)
 * AND wrong-named (decoy SAN vs the `to` host). With verification on (default)
 * the browser gets the branded 503 error page; with tls_skip_verify: true
 * Pomerium accepts it anyway - and skip wins even over a (wrong) tls_custom_ca.
 */

import { expect, test } from "@playwright/test";
import {
  openRoute,
  pomeriumErrorData,
  TLS_UNTRUSTED_CA,
  type EchoJson,
} from "../helpers/routes.js";
import { SNI_UPSTREAM_HOST } from "../setup/constants.js";

test.describe("Upstream TLS: skip verify", () => {
  test("default (verify on): untrusted cert + name mismatch is rejected (503)", async ({ page }) => {
    // Route: https://skip-verify-off.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: no tls_* options - the served decoy cert (SAN decoy.invalid) is
    //         untrusted by system roots AND doesn't match SNI "upstream-sni"

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "skipVerifyOff"));

    await test.step("Pomerium rejects the upstream handshake -> browser gets 503", () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(503);
    });

    await test.step("user sees Pomerium's branded error page with the Envoy TLS failure detail", async () => {
      await expect(page.locator("body")).toContainText(TLS_UNTRUSTED_CA.pageText);
      const data = await pomeriumErrorData(page);
      expect(data?.statusText ?? "", "Envoy statusText (%RESPONSE_CODE_DETAILS%)").toMatch(
        TLS_UNTRUSTED_CA.statusText,
      );
      expect(data?.responseFlags ?? "", "Envoy responseFlags").toMatch(
        TLS_UNTRUSTED_CA.responseFlags,
      );
    });
  });

  test("tls_skip_verify: true accepts the untrusted cert + name mismatch (200)", async ({ page }) => {
    // Route: https://skip-verify-on.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: tls_skip_verify = true - same untrusted, wrong-named decoy cert,
    //         but verification is disabled

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "skipVerifyOn"));

    const echo = await test.step("page loads (200): Pomerium skipped verification and proxied", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms the default SNI (the `to` host) was still sent", () => {
      // No name override, so the default SNI is the `to` host itself.
      expect(echo.tls.servername).toBe(SNI_UPSTREAM_HOST);
    });
  });

  test("tls_skip_verify overrides a (wrong) tls_custom_ca (200)", async ({ page }) => {
    // Route: https://skip-verify-wins.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: tls_skip_verify = true AND tls_custom_ca = base64(wrong-ca.crt) -
    //         the CA could never verify the served cert, but skip wins

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "skipVerifyWins"));

    const echo = await test.step("page loads (200): skip-verify won over the wrong custom CA", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms the SNI upstream answered", () => {
      expect(echo.mode, "reached the SNI upstream despite the wrong custom CA").toBe("sni");
    });
  });
});
