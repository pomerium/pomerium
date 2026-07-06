/**
 * Keycloak login helpers, lifted from
 * internal/acceptance/browser/helpers/authn-flow.ts.
 */

import { Page, expect } from "@playwright/test";
import { KEYCLOAK_HOSTNAME, MTLS_HOSTNAME, MTLS_URL, TEST_USER } from "../setup/constants.js";

const REALM_AUTH_PATH = "/realms/pomerium-e2e/protocol/openid-connect/auth";

/** Wait until the OIDC redirect chain lands on the Keycloak login form. */
export async function waitForKeycloakLoginPage(page: Page): Promise<void> {
  await page.waitForURL((url) => url.hostname === KEYCLOAK_HOSTNAME);
  expect(page.url()).toContain(REALM_AUTH_PATH);
}

/** Fill and submit the Keycloak login form. */
export async function submitLoginForm(
  page: Page,
  email: string,
  password: string
): Promise<void> {
  // Exact match for Password avoids matching the "Show password" toggle.
  await page.getByLabel(/username/i).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
}

/**
 * Drive the full OIDC round trip on the mTLS route: navigate (presenting the
 * page context's client certificate during the TLS handshake), sign in as the
 * test user on the Keycloak form, and wait for the redirect back.
 */
export async function signInOnMtlsRoute(page: Page): Promise<void> {
  await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
  await waitForKeycloakLoginPage(page);
  await submitLoginForm(page, TEST_USER.email, TEST_USER.password);
  await page.waitForURL((url) => url.hostname === MTLS_HOSTNAME);
}
