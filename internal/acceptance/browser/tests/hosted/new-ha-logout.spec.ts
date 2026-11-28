/**
 * New Hosted Authenticate (Hosted IdP) - Logout Tests
 *
 * Mirrors the old-HA Notion cases "HA.Log out.positive" / "HA.Log out.negative"
 * on the NEW flow (no dedicated Notion page yet): manual QA verified that both
 * flows show the SAME logout confirmation window, rendered by the hosted
 * service at authenticate.pomerium.app.
 *
 * Mechanics (code-verified):
 * - proxy/handlers_sign_out.go clears the route-domain session cookie BEFORE
 *   redirecting, and with idp_provider "hosted" the local authenticate skips
 *   its own SignOutConfirm page and revokes the local session before
 *   redirecting to the hosted end-session endpoint
 *   (authenticate/handlers_sign_out.go).
 * - Therefore after "Cancel" only the HOSTED session survives; route access is
 *   re-established via a silent SSO round trip. The invariant is "access
 *   without re-entering credentials", never "cookie survived".
 *
 * Gated on HOSTED_E2E=1 + HOSTED_TEST_EMAIL/PASSWORD (real hosted account).
 */

import { test, expect } from "@playwright/test";
import { urls, paths, timeouts } from "../../fixtures/test-data.js";
import {
  confirmHostedSignOut,
  expectSignInRedirect,
  expectUpstreamSeesUser,
  gotoStable,
  loginViaHosted,
  requireHostedUser,
  skipUnlessHostedE2E,
  waitForHostedSignInPage,
  waitForHostedSignOutConfirm,
} from "../../helpers/hosted.js";

const LOCAL_AUTHENTICATE_HOSTNAME = new URL(urls.authenticateHostedNew).hostname;
const ROUTE_HOSTNAME = new URL(urls.verifyHostedNew).hostname;

test.describe("New Hosted Authenticate: logout", () => {
  skipUnlessHostedE2E();

  test("N3: sign-out confirmed at the hosted service clears the session and forces re-authentication", async ({
    page,
  }) => {
    // Route: https://verify-hosted.localhost.pomerium.io:8444 -> http://upstream:8000
    // Config: config-hosted-new.yaml (local authenticate + idp_provider: hosted)
    const user = requireHostedUser();

    await test.step("log in via the hosted IdP", async () => {
      await loginViaHosted(page, { targetUrl: urls.verifyHostedNew, user });
    });

    await test.step("route sign-out leads to the confirmation page RENDERED BY the hosted service", async () => {
      // The local authenticate must only ever answer with redirects during
      // this chain - the confirm UI is the hosted service's, not a local
      // SignOutConfirm page (the observable new-HA delta).
      const localResponses: Array<{ url: string; status: number }> = [];
      const listener = (response: { url: () => string; status: () => number }) => {
        if (new URL(response.url()).hostname === LOCAL_AUTHENTICATE_HOSTNAME) {
          localResponses.push({ url: response.url(), status: response.status() });
        }
      };
      page.on("response", listener);
      await page.goto(`${urls.verifyHostedNew}${paths.signOut}`, {
        waitUntil: "domcontentloaded",
      });
      await waitForHostedSignOutConfirm(page);
      page.off("response", listener);

      expect(
        localResponses.length,
        "the chain must pass through the local authenticate service"
      ).toBeGreaterThan(0);
      for (const entry of localResponses) {
        expect(
          entry.status,
          `local authenticate must only redirect, never render (${entry.url})`
        ).toBeGreaterThanOrEqual(300);
        expect(entry.status).toBeLessThan(400);
      }
    });

    await test.step("confirm the sign-out on the hosted page", async () => {
      await confirmHostedSignOut(page, "confirm");
    });

    await test.step("the route session is gone", async () => {
      await expectSignInRedirect(page, urls.verifyHostedNew);
    });

    await test.step("revisiting the route forces a full re-authentication", async () => {
      // The confirm also ended the hosted session, so the credentials form
      // must appear on the hosted host (not a silent SSO) - which itself
      // proves the re-auth round trip.
      await gotoStable(page, urls.verifyHostedNew);
      await waitForHostedSignInPage(page);
    });
  });

  test("N4: sign-out cancelled at the hosted service keeps route access without re-entering credentials", async ({
    page,
  }) => {
    // Route: https://verify-hosted.localhost.pomerium.io:8444 -> http://upstream:8000
    // Config: config-hosted-new.yaml (local authenticate + idp_provider: hosted)
    const user = requireHostedUser();

    await test.step("log in via the hosted IdP", async () => {
      await loginViaHosted(page, { targetUrl: urls.verifyHostedNew, user });
    });

    await test.step("start sign-out and reach the hosted confirmation page", async () => {
      await page.goto(`${urls.verifyHostedNew}${paths.signOut}`, {
        waitUntil: "domcontentloaded",
      });
      await waitForHostedSignOutConfirm(page);
    });

    await test.step("cancel the sign-out", async () => {
      await confirmHostedSignOut(page, "cancel");
    });

    await test.step("the route is accessible again WITHOUT a credentials prompt", async () => {
      // The route cookie was already cleared when sign-out started, so a
      // silent SSO round trip through the hosted service is EXPECTED here -
      // the invariant is that no credentials form blocks the navigation.
      await gotoStable(page, urls.verifyHostedNew);
      await page.waitForURL((url) => url.hostname === ROUTE_HOSTNAME, {
        timeout: timeouts.long,
      });
    });

    await test.step("the same user's identity still reaches the upstream", async () => {
      await expectUpstreamSeesUser(page, urls.verifyHostedNew, user.email);
    });
  });
});
