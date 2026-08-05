/**
 * Keycloak OIDC login flow for the authenticated routes (control + mtlsClaims).
 * The generic Keycloak form primitives live in the shared package
 * (suites/shared/keycloak-login); this wraps the route-specific round trip.
 */

import type { Page } from "@playwright/test";
import { submitLoginForm, waitForKeycloakLoginPage } from "../../shared/keycloak-login.js";
import { KEYCLOAK_HOSTNAME, ROUTE_HOSTS, TEST_USER, routeUrl, type RouteKey } from "../setup/constants.js";
import { gotoStable } from "./nav.js";

/**
 * Navigate to an authenticated route and complete the OIDC round trip as the
 * test user, landing back on the route.
 */
export async function signInOnRoute(page: Page, key: RouteKey): Promise<void> {
  await gotoStable(page, routeUrl(key), { waitUntil: "domcontentloaded" });
  await waitForKeycloakLoginPage(page, KEYCLOAK_HOSTNAME);
  await submitLoginForm(page, TEST_USER.email, TEST_USER.password);
  await page.waitForURL((url) => url.hostname === ROUTE_HOSTS[key]);
}
