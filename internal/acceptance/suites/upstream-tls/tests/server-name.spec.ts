/**
 * Upstream TLS: tls_server_name / tls_upstream_server_name.
 * Test plan: Core.Upstream TLS (SNI + verification override, and precedence).
 *
 * The SNI upstream serves the backend cert (SAN backend.internal.example.com)
 * ONLY when the client sends that exact SNI, and a decoy cert otherwise. So a
 * route loads only when Pomerium both sends SNI = backend.internal.example.com
 * AND verifies against it - which is what tls_server_name /
 * tls_upstream_server_name control. The echo upstream reports the SNI it saw,
 * giving a direct wire-level assertion; a name the served cert doesn't carry
 * fails verification and the browser gets the branded 503 error page.
 */

import { expect, test } from "@playwright/test";
import {
  openRoute,
  pomeriumErrorData,
  TLS_SAN_MISMATCH,
  type EchoJson,
} from "../helpers/routes.js";
import { SNI_BACKEND_NAME } from "../setup/constants.js";

test.describe("Upstream TLS: server name (SNI + verification)", () => {
  test("no override: default SNI (the `to` host) fails against the served cert (503)", async ({ page }) => {
    // Route: https://sni-default.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt), no name override - Pomerium
    //         sends SNI "upstream-sni", so the upstream serves the decoy cert
    //         (SAN decoy.invalid), which never verifies against "upstream-sni"

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "sniDefault"));

    await test.step("Pomerium rejects the upstream handshake -> browser gets 503", () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(503);
    });

    await test.step('user sees the branded "Web Server is down" error page with Envoy TLS diagnostics', async () => {
      await expect(page.locator("body")).toContainText(TLS_SAN_MISMATCH.pageText);
      const data = await pomeriumErrorData(page);
      expect(data?.statusText ?? "", "Envoy statusText (%RESPONSE_CODE_DETAILS%)").toMatch(
        TLS_SAN_MISMATCH.statusText,
      );
      expect(data?.responseFlags ?? "", "Envoy responseFlags").toMatch(
        TLS_SAN_MISMATCH.responseFlags,
      );
    });
  });

  test("tls_server_name switches SNI + verification name (200)", async ({ page }) => {
    // Route: https://sni-server-name.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt),
    //         tls_server_name = backend.internal.example.com

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "sniServerName"));

    const echo = await test.step("page loads (200): the overridden name matched the backend cert", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms Pomerium sent the overridden SNI", () => {
      expect(echo.tls.servername, "SNI sent to the upstream").toBe(SNI_BACKEND_NAME);
    });
  });

  test("tls_server_name not on the cert's SAN is rejected (503)", async ({ page }) => {
    // Route: https://sni-server-name-bogus.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt), tls_server_name = bogus.invalid -
    //         the upstream serves the decoy cert (SAN decoy.invalid), which does
    //         not carry bogus.invalid, so verification fails

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "sniServerNameBogus"));

    await test.step("Pomerium rejects the upstream handshake -> browser gets 503", () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(503);
    });

    await test.step('user sees the branded "Web Server is down" error page with Envoy TLS diagnostics', async () => {
      await expect(page.locator("body")).toContainText(TLS_SAN_MISMATCH.pageText);
      const data = await pomeriumErrorData(page);
      expect(data?.statusText ?? "", "Envoy statusText (%RESPONSE_CODE_DETAILS%)").toMatch(
        TLS_SAN_MISMATCH.statusText,
      );
      expect(data?.responseFlags ?? "", "Envoy responseFlags").toMatch(
        TLS_SAN_MISMATCH.responseFlags,
      );
    });
  });

  test("tls_upstream_server_name switches SNI + verification name (200)", async ({ page }) => {
    // Route: https://sni-upstream-name.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt),
    //         tls_upstream_server_name = backend.internal.example.com

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "sniUpstreamName"));

    const echo = await test.step("page loads (200): the overridden name matched the backend cert", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms Pomerium sent the overridden SNI", () => {
      expect(echo.tls.servername, "SNI sent to the upstream").toBe(SNI_BACKEND_NAME);
    });
  });

  test("tls_upstream_server_name not on the cert's SAN is rejected (503)", async ({ page }) => {
    // Route: https://sni-upstream-name-bogus.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt), tls_upstream_server_name = bogus.invalid -
    //         the served decoy cert does not carry bogus.invalid, so verification fails

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "sniUpstreamBogus"));

    await test.step("Pomerium rejects the upstream handshake -> browser gets 503", () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(503);
    });

    await test.step('user sees the branded "Web Server is down" error page with Envoy TLS diagnostics', async () => {
      await expect(page.locator("body")).toContainText(TLS_SAN_MISMATCH.pageText);
      const data = await pomeriumErrorData(page);
      expect(data?.statusText ?? "", "Envoy statusText (%RESPONSE_CODE_DETAILS%)").toMatch(
        TLS_SAN_MISMATCH.statusText,
      );
      expect(data?.responseFlags ?? "", "Envoy responseFlags").toMatch(
        TLS_SAN_MISMATCH.responseFlags,
      );
    });
  });

  test("tls_upstream_server_name takes precedence over tls_server_name", async ({ page }) => {
    // Route: https://sni-precedence.localhost.pomerium.io:8443 -> https://upstream-sni:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt),
    //         tls_server_name = bogus.invalid (WRONG) AND
    //         tls_upstream_server_name = backend.internal.example.com (RIGHT) -
    //         a 200 with the backend SNI proves tls_upstream_server_name won for
    //         both the SNI sent and the name verified

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "sniPrecedence"));

    const echo = await test.step("page loads (200): the winning name matched the backend cert", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms tls_upstream_server_name drove the SNI", () => {
      expect(echo.tls.servername, "tls_upstream_server_name drove the SNI").toBe(SNI_BACKEND_NAME);
    });
  });
});
