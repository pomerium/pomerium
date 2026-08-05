/**
 * Upstream TLS: tls_server_name / tls_upstream_server_name.
 * Test plan: Core.Upstream TLS (SNI + verification override, and precedence).
 *
 * The SNI upstream serves the backend cert (SAN backend.internal.example.com)
 * ONLY when the client sends that exact SNI, and a decoy cert otherwise. So a
 * route loads only when Pomerium both sends SNI = backend.internal.example.com
 * AND verifies against it - which is what tls_server_name /
 * tls_upstream_server_name control. The echo upstream reports the SNI it saw,
 * giving a direct wire-level assertion.
 */

import { expect, test } from "@playwright/test";
import { expectHandshake503, gotoEcho } from "../helpers/routes.js";
import { SNI_BACKEND_NAME } from "../setup/constants.js";

test.describe("Upstream TLS: server name (SNI + verification)", () => {
  test("no override: default SNI (the `to` host) fails against the served cert (503)", async ({ page }) => {
    await expectHandshake503(page, "sniDefault");
  });

  test("tls_server_name switches SNI + verification name (200)", async ({ page }) => {
    const echo = await gotoEcho(page, "sniServerName");
    expect(echo.tls.servername, "SNI sent to the upstream").toBe(SNI_BACKEND_NAME);
  });

  test("tls_server_name not on the cert's SAN is rejected (503)", async ({ page }) => {
    await expectHandshake503(page, "sniServerNameBogus");
  });

  test("tls_upstream_server_name switches SNI + verification name (200)", async ({ page }) => {
    const echo = await gotoEcho(page, "sniUpstreamName");
    expect(echo.tls.servername, "SNI sent to the upstream").toBe(SNI_BACKEND_NAME);
  });

  test("tls_upstream_server_name not on the cert's SAN is rejected (503)", async ({ page }) => {
    await expectHandshake503(page, "sniUpstreamBogus");
  });

  test("tls_upstream_server_name takes precedence over tls_server_name", async ({ page }) => {
    // tls_server_name is WRONG (bogus), tls_upstream_server_name is RIGHT. A 200
    // with the backend SNI proves tls_upstream_server_name won for both the SNI
    // sent and the name verified.
    const echo = await gotoEcho(page, "sniPrecedence");
    expect(echo.tls.servername, "tls_upstream_server_name drove the SNI").toBe(SNI_BACKEND_NAME);
  });
});
