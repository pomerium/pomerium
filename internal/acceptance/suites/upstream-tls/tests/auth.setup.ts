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
import { submitLoginForm, waitForKeycloakLoginPage } from "../../shared/keycloak-login.js";
import { gotoStable } from "../helpers/nav.js";
import {
  KEYCLOAK_HOSTNAME,
  ROUTE_HOSTS,
  STORAGE_STATE,
  TEST_USER,
  routeUrl,
} from "../setup/constants.js";

setup("authenticate via Keycloak and save the session", async ({ page }) => {
  // Route: https://verify.localhost.pomerium.io:8443 (the control route; the
  // session it establishes is valid for every route host).

  await setup.step("anonymous user opens the route and is redirected to Keycloak", async () => {
    await gotoStable(page, routeUrl("control"), { waitUntil: "domcontentloaded" });
    await waitForKeycloakLoginPage(page, KEYCLOAK_HOSTNAME);
  });

  await setup.step("user submits the Keycloak login form", async () => {
    await submitLoginForm(page, TEST_USER.email, TEST_USER.password);
  });

  await setup.step("IdP redirects back to the route with a Pomerium session", async () => {
    // A broken login fails here (and gates the behavior specs).
    await page.waitForURL((url) => url.hostname === ROUTE_HOSTS.control);
  });

  await setup.step("save the browser session for the behavior specs (storageState)", async () => {
    await page.context().storageState({ path: STORAGE_STATE });
  });
});
