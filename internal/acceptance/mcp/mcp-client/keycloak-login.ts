// Keycloak browser-login helpers.
//
// These mirror internal/acceptance/browser/helpers/authn-flow.ts
// (`waitForLoginPage` / `submitLoginForm`) against the SAME Keycloak realm. They
// are kept local (rather than imported from the browser package) so this suite
// loads a single Playwright instance — importing the browser package's
// @playwright/test would pull in a second test-runner copy with incompatible
// types and global state.

import { expect, type Page } from "@playwright/test";
import type { TestUser } from "../../browser/fixtures/users.js";

const KEYCLOAK_HOST = "keycloak.localhost.pomerium.io";
const REALM_AUTH_PATH = "/realms/pomerium-e2e/protocol/openid-connect/auth";

/** Wait until the browser is on the Keycloak login page. */
export async function waitForLoginPage(page: Page): Promise<void> {
  await page.waitForURL((url) => url.hostname === KEYCLOAK_HOST);
  expect(page.url()).toContain(REALM_AUTH_PATH);
}

/** Fill and submit the Keycloak username/password form. */
export async function submitLoginForm(page: Page, user: TestUser): Promise<void> {
  await page.getByLabel(/username/i).fill(user.email);
  // Exact match avoids matching the "Show password" toggle.
  await page.getByLabel("Password", { exact: true }).fill(user.password);
  await page.getByRole("button", { name: /sign in/i }).click();
}
