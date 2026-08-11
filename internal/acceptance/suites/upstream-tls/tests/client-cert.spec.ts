/**
 * Upstream TLS: tls_client_cert / tls_client_key (+ _file variants).
 * Test plan: Core.Upstream TLS (base64 mTLS + file-path mTLS to upstream).
 *
 * The upstream requires a client certificate (Node echo, requestCert +
 * rejectUnauthorized). As a logged-in user, the page loads when Pomerium
 * presents its client cert (inline base64 pair or file pair) and the upstream
 * reports the verified subject; with no client cert configured the upstream
 * rejects the handshake and the browser gets the branded 503 error page.
 */

import { expect, test } from "@playwright/test";
import {
  openRoute,
  pomeriumErrorData,
  UPSTREAM_TERMINATED,
  type EchoJson,
} from "../helpers/routes.js";

test.describe("Upstream TLS: client certificate", () => {
  test("tls_client_cert + tls_client_key (inline) authenticate to the mTLS upstream", async ({ page }) => {
    // Route: https://client-cert.localhost.pomerium.io:8443 -> https://upstream-mtls:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt),
    //         tls_client_cert + tls_client_key = base64(pomerium-client.{crt,key})

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "clientCert"));

    const echo = await test.step("page loads (200): Pomerium completed the mTLS handshake and proxied", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms it verified Pomerium's client certificate", () => {
      expect(echo.tls.authorized, "upstream verified the client cert").toBe(true);
      expect(echo.tls.peerCertificate?.subject?.CN).toBe("pomerium-client");
    });
  });

  test("tls_client_cert_file + tls_client_key_file authenticate to the mTLS upstream", async ({ page }) => {
    // Route: https://client-cert-file.localhost.pomerium.io:8443 -> https://upstream-mtls:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt),
    //         tls_client_cert_file + tls_client_key_file = /certs/upstream/pomerium-client.{crt,key}

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "clientCertFile"));

    const echo = await test.step("page loads (200): Pomerium completed the mTLS handshake and proxied", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms it verified Pomerium's client certificate", () => {
      expect(echo.tls.authorized, "upstream verified the client cert").toBe(true);
      expect(echo.tls.peerCertificate?.subject?.CN).toBe("pomerium-client");
    });
  });

  test("no client certificate configured: the mTLS upstream rejects the handshake (503)", async ({ page }) => {
    // Route: https://client-cert-missing.localhost.pomerium.io:8443 -> https://upstream-mtls:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt) only - no tls_client_cert*,
    //         so the upstream (requestCert + rejectUnauthorized) refuses Pomerium

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "clientCertMissing"));

    await test.step("the upstream requires a client cert Pomerium doesn't have -> browser gets 503", () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(503);
    });

    await test.step('user sees the branded "Web Server is down" error page with Envoy termination diagnostics', async () => {
      await expect(page.locator("body")).toContainText(UPSTREAM_TERMINATED.pageText);
      const data = await pomeriumErrorData(page);
      expect(data?.statusText ?? "", "Envoy statusText (%RESPONSE_CODE_DETAILS%)").toMatch(
        UPSTREAM_TERMINATED.statusText,
      );
      expect(data?.responseFlags ?? "", "Envoy responseFlags").toMatch(
        UPSTREAM_TERMINATED.responseFlags,
      );
    });
  });
});
