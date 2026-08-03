/**
 * E2E specs for Pomerium's global `downstream_mtls` settings in the default
 * enforcement mode (`policy_with_default_deny`).
 *
 * Behavior notes (verified against the pomerium source):
 * - Envoy REQUESTS but does not REQUIRE a client certificate
 *   (TrustChainVerification: ACCEPT_UNTRUSTED), so the TLS handshake succeeds
 *   even with a missing or untrusted certificate. Enforcement happens in the
 *   authorize service, which denies with HTTP 495 and an HTML error page
 *   BEFORE any redirect to the IdP.
 * - Control-plane routes (/healthz, /.pomerium/, the authenticate host) are
 *   exempt from the default deny.
 * - TLS-level rejection only happens under `enforcement: reject_connection`
 *   (covered by TC-CC-14 in enforcement.spec.ts).
 */

import { test, expect } from "@playwright/test";
import { newContextWithCert, type ClientCertType } from "../helpers/mtls.js";
import { signInOnMtlsRoute } from "../helpers/login.js";
import { startPomerium, type StartedPomerium } from "../setup/containers.js";
import { baseConfigFile } from "../setup/pomerium-config.js";
import { MTLS_HOSTNAME, MTLS_URL } from "../setup/constants.js";

let pomerium: StartedPomerium;

test.beforeAll(async () => {
  pomerium = await startPomerium({ configFile: baseConfigFile() });
});

test.afterAll(async () => {
  await pomerium?.stop();
});

test.describe("downstream mTLS (enforcement: policy_with_default_deny)", () => {
  test("valid client cert + Keycloak login reaches the upstream", async ({ browser }) => {
    const context = await newContextWithCert(browser, "valid", MTLS_URL);
    try {
      const page = await context.newPage();

      // First navigation: TLS handshake presents the client certificate,
      // then the OIDC redirect chain leads through the Keycloak login form
      // and back to the mTLS route.
      await signInOnMtlsRoute(page);

      // Fresh navigation with an established session: whoami echoes the
      // request headers, which must include the identity header Pomerium
      // injects (jwt_claims_headers), proving mTLS + OIDC end to end.
      const response = await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
      expect(response).not.toBeNull();
      expect(response!.status()).toBe(200);
      expect(await response!.text()).toMatch(/X-Pomerium-Claim-Email:.*alice@company\.com/i);
    } finally {
      await context.close();
    }
  });

  // The handshake ACCEPTS a missing or untrusted certificate by design in
  // this enforcement mode; the request is then denied by authorize.
  const denied: Array<{ title: string; cert: ClientCertType | null }> = [
    { title: "no client cert", cert: null },
    { title: "client cert from an untrusted CA", cert: "wrong-ca" },
  ];

  for (const { title, cert } of denied) {
    test(`${title} is denied with 495 before any IdP redirect`, async ({ browser }) => {
      const context = await newContextWithCert(browser, cert, MTLS_URL);
      try {
        const page = await context.newPage();
        const response = await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
        expect(response).not.toBeNull();
        expect(response!.status()).toBe(495);
        // Denied at the edge: no redirect to Keycloak happened.
        expect(new URL(page.url()).hostname).toBe(MTLS_HOSTNAME);
        await expect(page.locator("body")).toContainText(/client certificate/i);
      } finally {
        await context.close();
      }
    });
  }

  test("control-plane /healthz is exempt from the default deny", async ({ browser }) => {
    const context = await newContextWithCert(browser, null, MTLS_URL);
    try {
      const page = await context.newPage();
      const response = await page.goto(`${MTLS_URL}/healthz`, {
        waitUntil: "domcontentloaded",
      });
      expect(response).not.toBeNull();
      expect(response!.status()).toBe(200);
    } finally {
      await context.close();
    }
  });
});
