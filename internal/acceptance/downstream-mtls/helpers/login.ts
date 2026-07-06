/**
 * Keycloak login helpers, lifted from
 * internal/acceptance/browser/helpers/authn-flow.ts.
 */

import { Page, expect } from "@playwright/test";

const KEYCLOAK_HOSTNAME = "keycloak.localhost.pomerium.io";
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
