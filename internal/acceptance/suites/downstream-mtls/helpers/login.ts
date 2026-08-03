/**
 * Keycloak login flow for the mTLS route. The generic Keycloak form primitives
 * live in the shared package (suites/shared/keycloak-login); this keeps the
 * mTLS-route-specific OIDC round trip that the specs consume.
 */

import { Page } from "@playwright/test";
import {
  submitLoginForm,
  waitForKeycloakLoginPage,
} from "../../shared/keycloak-login.js";
import { KEYCLOAK_HOSTNAME, MTLS_HOSTNAME, MTLS_URL, TEST_USER } from "../setup/constants.js";
import { gotoStable } from "./nav.js";

/**
 * Drive the full OIDC round trip on the mTLS route: navigate (presenting the
 * page context's client certificate during the TLS handshake), sign in as the
 * test user on the Keycloak form, and wait for the redirect back.
 */
export async function signInOnMtlsRoute(page: Page): Promise<void> {
  await gotoStable(page, MTLS_URL, { waitUntil: "domcontentloaded" });
  await waitForKeycloakLoginPage(page, KEYCLOAK_HOSTNAME);
  await submitLoginForm(page, TEST_USER.email, TEST_USER.password);
  await page.waitForURL((url) => url.hostname === MTLS_HOSTNAME);
}
