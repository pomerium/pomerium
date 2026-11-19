/**
 * Hosted Authenticate priority over configured IdP settings
 *
 * Notion: QA -> Test Plans -> Core Test Plan -> Authentication -> Hosted
 *         Authenticate -> "HA.HA priority over IdP".
 *
 * The instance under test has BOTH a hosted authenticate_service_url AND a
 * full idp_provider block for the local compose Keycloak. Flow selection keys
 * purely off the authenticate hostname (config/options.go
 * UseStatelessAuthenticateFlow), so sign-in must go to
 * authenticate.pomerium.app and the browser must never touch Keycloak.
 *
 * This test deliberately never completes a login: the first redirect is a
 * purely local decision, so the hosted service's handling of the (unknown)
 * sealed pomerium_idp_id cannot fail it.
 *
 * Gated on HOSTED_E2E=1 only - no account needed.
 */

import { test, expect } from "@playwright/test";
import { urls, paths } from "../../fixtures/test-data.js";
import {
  expectSignInRedirect,
  skipUnlessHostedE2E,
  trackRequests,
  waitForHostedSignInPage,
} from "../../helpers/hosted.js";

const KEYCLOAK_HOSTNAME = new URL(urls.keycloak).hostname;

test.describe("Hosted authenticate takes priority over configured IdP", () => {
  skipUnlessHostedE2E();

  test("O6: with both hosted authenticate URL and Keycloak idp_* configured, sign-in goes to the hosted service", async ({
    page,
  }) => {
    // Route: https://verify-hosted-priority.localhost.pomerium.io:8446 -> http://upstream:8000
    // Config: authenticate_service_url: https://authenticate.pomerium.app PLUS a
    //         full idp_provider: oidc block for the compose Keycloak
    //         (config-hosted-priority.yaml)

    await test.step("the first redirect targets the hosted service, not Keycloak", async () => {
      const location = await expectSignInRedirect(page, urls.verifyHostedPriority);
      expect(location.origin, "sign-in must go to the hosted service").toBe(
        urls.hostedAuthenticate
      );
      expect(location.pathname).toBe(paths.signIn);
      expect(
        [...location.searchParams.keys()].sort(),
        "stateless flow: HPKE pair only"
      ).toEqual(["k", "q"]);
    });

    await test.step("browser navigation lands on the hosted sign-in and never touches Keycloak", async () => {
      const keycloakRequests = trackRequests(
        page,
        (url) => url.hostname === KEYCLOAK_HOSTNAME
      );
      await page.goto(urls.verifyHostedPriority, { waitUntil: "domcontentloaded" });
      await waitForHostedSignInPage(page);
      keycloakRequests.dispose();
      expect(
        keycloakRequests.urls(),
        "the configured Keycloak IdP must never be contacted"
      ).toEqual([]);
    });
  });
});
