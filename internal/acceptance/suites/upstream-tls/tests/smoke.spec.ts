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
import { gotoEcho, verifyClaims } from "../helpers/routes.js";
import { TEST_USER } from "../setup/constants.js";

test.describe("Scaffolding smoke", () => {
  test("control route injects identity headers", async ({ page }) => {
    const claims = await verifyClaims(page);
    expect(claims["x-pomerium-claim-email"]).toContain(TEST_USER.email);
  });

  test("full stack: identity headers AND client cert reach the mTLS upstream", async ({ page }) => {
    const echo = await gotoEcho(page, "mtlsClaims");
    expect(echo.claims["x-pomerium-claim-email"], "identity header reached the upstream").toContain(
      TEST_USER.email,
    );
    expect(echo.tls.authorized, "upstream verified Pomerium's client certificate").toBe(true);
    expect(echo.tls.peerCertificate?.subject?.CN, "client cert subject").toBe("pomerium-client");
  });
});
