/**
 * Upstream TLS: tls_custom_ca / tls_custom_ca_file.
 * Test plan: Core.Upstream TLS (tls_custom_ca, tls_custom_ca_file).
 *
 * As a logged-in user, reaching an upstream signed by a private CA supplied per
 * route (base64 tls_custom_ca or a tls_custom_ca_file path) loads the page. The
 * custom CA REPLACES the system trust bundle for that route, so an unrelated CA
 * - or no CA at all - fails the upstream handshake and the browser gets the
 * branded 503 upstream error page.
 */

import { expect, test } from "@playwright/test";
import {
  openRoute,
  pomeriumErrorData,
  TLS_UNTRUSTED_CA,
  type EchoJson,
} from "../helpers/routes.js";
import { TLS_UPSTREAM_HOST } from "../setup/constants.js";

test.describe("Upstream TLS: custom CA", () => {
  test("tls_custom_ca (base64) trusts the upstream CA", async ({ page }) => {
    // Route: https://custom-ca.localhost.pomerium.io:8443 -> https://upstream-tls:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt), the CA that signed the upstream's cert

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "customCa"));

    const echo = await test.step("page loads (200): Pomerium trusted the upstream and proxied", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms a real TLS session with default SNI (the `to` host)", () => {
      expect(echo.tls.protocol).toMatch(/^TLSv1\.[23]$/);
      expect(echo.tls.servername, "default SNI is the `to` host").toBe(TLS_UPSTREAM_HOST);
    });
  });

  test("tls_custom_ca_file (path) trusts the upstream CA", async ({ page }) => {
    // Route: https://custom-ca-file.localhost.pomerium.io:8443 -> https://upstream-tls:4433
    // Config: tls_custom_ca_file = /certs/upstream/upstream-ca.crt (mounted into the container)

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "customCaFile"));

    const echo = await test.step("page loads (200): Pomerium trusted the upstream and proxied", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms a real TLS session with default SNI (the `to` host)", () => {
      expect(echo.tls.protocol).toMatch(/^TLSv1\.[23]$/);
      expect(echo.tls.servername, "default SNI is the `to` host").toBe(TLS_UPSTREAM_HOST);
    });
  });

  test("an unrelated custom CA is rejected (503)", async ({ page }) => {
    // Route: https://custom-ca-wrong.localhost.pomerium.io:8443 -> https://upstream-tls:4433
    // Config: tls_custom_ca = base64(wrong-ca.crt), a CA that did NOT sign the upstream's cert

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "customCaWrong"));

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

  test("no custom CA: the private upstream CA is untrusted by system roots (503)", async ({ page }) => {
    // Route: https://custom-ca-none.localhost.pomerium.io:8443 -> https://upstream-tls:4433
    // Config: no tls_* options - verification uses the system roots, which do
    //         not include the private upstream CA

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "customCaNone"));

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
});
