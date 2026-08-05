/**
 * Auth setup: log in once through the real IdP and save the browser session.
 *
 * Runs as a Playwright "setup" project before the behavior specs
 * (playwright.config.ts). It drives the actual Keycloak login form on the
 * control route and persists the session to storageState so every behavior spec
 * runs as this authenticated user (first hit to each route subdomain then SSOs
 * silently). Identity-header injection is asserted in smoke.spec.ts.
 */

import { test as setup } from "@playwright/test";
import { signInOnRoute } from "../helpers/login.js";
import { STORAGE_STATE } from "../setup/constants.js";

setup("authenticate via Keycloak and save the session", async ({ page }) => {
  // signInOnRoute waits for the post-login redirect back to the route, so a
  // broken login fails the setup project here (and gates the behavior specs).
  await signInOnRoute(page, "control");
  await page.context().storageState({ path: STORAGE_STATE });
});
