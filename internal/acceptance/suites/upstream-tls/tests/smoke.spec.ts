/**
 * Scaffolding smoke test (user perspective).
 * Test plan: Core.Upstream TLS (end-to-end path with a real IdP + real mTLS).
 *
 * The setup project (auth.setup.ts) has already logged this browser in through
 * Keycloak; these tests navigate as that user and assert on what the browser
 * receives:
 *   1. Pomerium injects identity headers on the plain-HTTP control route.
 *   2. The same identity headers AND Pomerium's client certificate reach an
 *      mTLS-required upstream over a real TLS handshake (tls_custom_ca +
 *      tls_client_cert_file), read from the echo upstream's JSON response.
 */

import { expect, test } from "@playwright/test";
import { openRoute, type EchoJson } from "../helpers/routes.js";
import { TEST_USER } from "../setup/constants.js";

test.describe("Scaffolding smoke", () => {
  test("control route injects identity headers", async ({ page }) => {
    // Route: https://verify.localhost.pomerium.io:8443 -> http://upstream:8000 (pomerium/verify)
    // Config: pass_identity_headers + global jwt_claims_headers (X-Pomerium-Claim-Email)

    const resp = await test.step("signed-in user opens the route's /json in the browser", () =>
      openRoute(page, "control", "/json"));

    const claims = await test.step("verify's /json echoes the request headers it received", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status(), "control /json must reach the upstream").toBe(200);
      const body = (await resp!.json()) as { headers?: Record<string, unknown> };
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(body.headers ?? {})) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
      }
      return headers;
    });

    await test.step("Pomerium injected the identity header for the logged-in user", () => {
      expect(claims["x-pomerium-claim-email"]).toContain(TEST_USER.email);
    });
  });

  test("full stack: identity headers AND client cert reach the mTLS upstream", async ({ page }) => {
    // Route: https://mtls-claims.localhost.pomerium.io:8443 -> https://upstream-mtls:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt), tls_client_cert_file +
    //         tls_client_key_file = /certs/upstream/pomerium-client.{crt,key},
    //         pass_identity_headers

    const resp = await test.step("signed-in user opens the route in the browser", () =>
      openRoute(page, "mtlsClaims"));

    const echo = await test.step("page loads (200): Pomerium completed the mTLS handshake and proxied", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms identity header + verified client certificate", () => {
      expect(echo.claims["x-pomerium-claim-email"], "identity header reached the upstream").toContain(
        TEST_USER.email,
      );
      expect(echo.tls.authorized, "upstream verified Pomerium's client certificate").toBe(true);
      expect(echo.tls.peerCertificate?.subject?.CN, "client cert subject").toBe("pomerium-client");
    });
  });
});
