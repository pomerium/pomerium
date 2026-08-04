// Shared Keycloak browser-login primitives for the container-based acceptance
// suites (suites/mcp, suites/downstream-mtls). Both drive the SAME Keycloak
// realm login form; each suite wraps these with its own route-specific flow.
//
// Kept dependency-light (only @playwright/test, resolved from the hoisted
// workspace node_modules) so a suite loads a single Playwright instance.

import { expect, type Page } from "@playwright/test";

const REALM_AUTH_PATH = "/realms/pomerium-e2e/protocol/openid-connect/auth";

/** Wait until the OIDC redirect chain lands on the Keycloak login form. */
export async function waitForKeycloakLoginPage(
  page: Page,
  keycloakHostname: string,
): Promise<void> {
  await page.waitForURL((url) => url.hostname === keycloakHostname);
  expect(page.url()).toContain(REALM_AUTH_PATH);
}

/** Fill and submit the Keycloak username/password form. */
export async function submitLoginForm(
  page: Page,
  email: string,
  password: string,
): Promise<void> {
  await page.getByLabel(/username/i).fill(email);
  // Exact match for Password avoids matching the "Show password" toggle.
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
}
