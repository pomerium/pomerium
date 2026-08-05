/**
 * Upstream TLS: tls_client_cert / tls_client_key (+ _file variants).
 * Test plan: Core.Upstream TLS (base64 mTLS + file-path mTLS to upstream).
 *
 * The upstream requires a client certificate (Node echo, requestCert +
 * rejectUnauthorized). As a logged-in user, the page loads when Pomerium
 * presents its client cert (inline base64 pair or file pair) and the upstream
 * reports the verified subject; with no client cert configured the upstream
 * rejects the handshake (503).
 */

import { expect, test } from "@playwright/test";
import { expectHandshake503, gotoEcho } from "../helpers/routes.js";

test.describe("Upstream TLS: client certificate", () => {
  test("tls_client_cert + tls_client_key (inline) authenticate to the mTLS upstream", async ({ page }) => {
    const echo = await gotoEcho(page, "clientCert");
    expect(echo.tls.authorized, "upstream verified the client cert").toBe(true);
    expect(echo.tls.peerCertificate?.subject?.CN).toBe("pomerium-client");
  });

  test("tls_client_cert_file + tls_client_key_file authenticate to the mTLS upstream", async ({ page }) => {
    const echo = await gotoEcho(page, "clientCertFile");
    expect(echo.tls.authorized, "upstream verified the client cert").toBe(true);
    expect(echo.tls.peerCertificate?.subject?.CN).toBe("pomerium-client");
  });

  test("no client certificate configured: the mTLS upstream rejects the handshake (503)", async ({ page }) => {
    await expectHandshake503(page, "clientCertMissing");
  });
});
