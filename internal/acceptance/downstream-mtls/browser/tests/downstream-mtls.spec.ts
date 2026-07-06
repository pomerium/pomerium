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
 *   (future spec; see isTLSHandshakeError in ../helpers/mtls.js).
 */

import { test, expect } from "@playwright/test";
import { newContextWithCert, newContextWithoutCert } from "../helpers/mtls.js";
import { waitForKeycloakLoginPage, submitLoginForm } from "../helpers/login.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

const MTLS_URL = requireEnv("MTLS_URL");
const TEST_USER_EMAIL = requireEnv("TEST_USER_EMAIL");
const TEST_USER_PASSWORD = requireEnv("TEST_USER_PASSWORD");

const mtlsHostname = new URL(MTLS_URL).hostname;

test.describe("downstream mTLS (enforcement: policy_with_default_deny)", () => {
  test("valid client cert + Keycloak login reaches the upstream", async ({ browser }) => {
    const context = await newContextWithCert(browser, "valid", MTLS_URL);
    try {
      const page = await context.newPage();

      // First navigation: TLS handshake presents the client certificate,
      // then the OIDC redirect chain leads to the Keycloak login form.
      await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
      await waitForKeycloakLoginPage(page);
      await submitLoginForm(page, TEST_USER_EMAIL, TEST_USER_PASSWORD);

      // The auth round trip ends back on the mTLS route.
      await page.waitForURL((url) => url.hostname === mtlsHostname);

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

  test("no client cert is denied with 495 before any IdP redirect", async ({ browser }) => {
    const context = await newContextWithoutCert(browser);
    try {
      const page = await context.newPage();
      const response = await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
      expect(response).not.toBeNull();
      expect(response!.status()).toBe(495);
      // Denied at the edge: no redirect to Keycloak happened.
      expect(new URL(page.url()).hostname).toBe(mtlsHostname);
      await expect(page.locator("body")).toContainText(/client certificate/i);
    } finally {
      await context.close();
    }
  });

  test("client cert from an untrusted CA is denied with 495", async ({ browser }) => {
    const context = await newContextWithCert(browser, "wrong-ca", MTLS_URL);
    try {
      const page = await context.newPage();
      // The handshake ACCEPTS the untrusted certificate by design in this
      // enforcement mode; the request is then denied by authorize.
      const response = await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
      expect(response).not.toBeNull();
      expect(response!.status()).toBe(495);
      expect(new URL(page.url()).hostname).toBe(mtlsHostname);
      await expect(page.locator("body")).toContainText(/client certificate/i);
    } finally {
      await context.close();
    }
  });

  test("control-plane /healthz is exempt from the default deny", async ({ browser }) => {
    const context = await newContextWithoutCert(browser);
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
