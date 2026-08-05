/**
 * Upstream TLS: tls_custom_ca / tls_custom_ca_file.
 * Test plan: Core.Upstream TLS (tls_custom_ca, tls_custom_ca_file).
 *
 * As a logged-in user, reaching an upstream signed by a private CA supplied per
 * route (base64 tls_custom_ca or a tls_custom_ca_file path) loads the page. The
 * custom CA REPLACES the system trust bundle for that route, so an unrelated CA
 * - or no CA at all - fails the upstream handshake (503 error page).
 */

import { expect, test } from "@playwright/test";
import { expectHandshake503, gotoEcho } from "../helpers/routes.js";

test.describe("Upstream TLS: custom CA", () => {
  test("tls_custom_ca (base64) trusts the upstream CA", async ({ page }) => {
    const echo = await gotoEcho(page, "customCa");
    expect(echo.tls.protocol).toMatch(/^TLSv1\.[23]$/);
  });

  test("tls_custom_ca_file (path) trusts the upstream CA", async ({ page }) => {
    await gotoEcho(page, "customCaFile");
  });

  test("an unrelated custom CA is rejected (503)", async ({ page }) => {
    await expectHandshake503(page, "customCaWrong");
  });

  test("no custom CA: the private upstream CA is untrusted by system roots (503)", async ({ page }) => {
    await expectHandshake503(page, "customCaNone");
  });
});
