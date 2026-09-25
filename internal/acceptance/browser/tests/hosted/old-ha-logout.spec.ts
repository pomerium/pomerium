/**
 * Old Hosted Authenticate (stateless flow) - Logout Tests
 *
 * Notion: QA -> Test Plans -> Core Test Plan -> Authentication -> Hosted
 *         Authenticate -> "HA.Log out.positive" / "HA.Log out.negative".
 *
 * Mechanics (code-verified): the proxy's /.pomerium/sign_out clears the
 * route-domain session cookie FIRST, then redirects to the hosted service's
 * signed sign-out URL, which renders the confirmation window. After "Cancel"
 * only the HOSTED session survives, so route access is re-established via a
 * silent SSO round trip - the invariant is "access without re-entering
 * credentials", never "cookie survived".
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

const ROUTE_HOSTNAME = new URL(urls.verifyHostedOld).hostname;

test.describe("Old Hosted Authenticate: logout", () => {
  skipUnlessHostedE2E();

  test("O3: sign-out confirmed at the hosted page clears the session and forces re-authentication", async ({
    page,
  }) => {
    // Route: https://verify-hosted-old.localhost.pomerium.io:8445 -> http://upstream:8000
    // Config: config-hosted-old.yaml (stateless flow; sign-out UI lives at the
    //         hosted service)
    const user = requireHostedUser();

    await test.step("log in via the hosted authenticate", async () => {
      await loginViaHosted(page, { targetUrl: urls.verifyHostedOld, user });
    });

    await test.step("route sign-out redirects to the hosted service's SIGNED sign-out URL", async () => {
      // NOTE: browser navigation, never page.request - the API context shares
      // the cookie jar and a request-context GET would clear the session
      // out-of-band before the browser flow runs.
      const signOutHop = page.waitForRequest(
        (req) => req.url().startsWith(`${urls.hostedAuthenticate}${paths.signOut}`),
        { timeout: timeouts.long }
      );
      await page.goto(`${urls.verifyHostedOld}${paths.signOut}`, {
        waitUntil: "domcontentloaded",
      });
      await waitForHostedSignOutConfirm(page);

      const hop = new URL((await signOutHop).url());
      expect(hop.searchParams.get("pomerium_issued"), "signed URL: issued ts").toBeTruthy();
      expect(hop.searchParams.get("pomerium_expiry"), "signed URL: expiry ts").toBeTruthy();
      expect(hop.searchParams.get("pomerium_signature"), "signed URL: HMAC").toBeTruthy();
    });

    await test.step("confirm the sign-out on the hosted page", async () => {
      await confirmHostedSignOut(page, "confirm");
    });

    await test.step("the route session is gone", async () => {
      await expectSignInRedirect(page, urls.verifyHostedOld);
    });

    await test.step("revisiting the route forces a full re-authentication", async () => {
      // Confirming also ended the hosted session, so the credentials form
      // must appear on the hosted host (not a silent SSO) - which itself
      // proves the re-auth round trip.
      await gotoStable(page, urls.verifyHostedOld);
      await waitForHostedSignInPage(page);
    });
  });

  test("O4: sign-out cancelled at the hosted page keeps route access without re-entering credentials", async ({
    page,
  }) => {
    // Route: https://verify-hosted-old.localhost.pomerium.io:8445 -> http://upstream:8000
    // Config: config-hosted-old.yaml (stateless flow)
    const user = requireHostedUser();

    await test.step("log in via the hosted authenticate", async () => {
      await loginViaHosted(page, { targetUrl: urls.verifyHostedOld, user });
    });

    await test.step("start sign-out and reach the hosted confirmation page", async () => {
      await page.goto(`${urls.verifyHostedOld}${paths.signOut}`, {
        waitUntil: "domcontentloaded",
      });
      await waitForHostedSignOutConfirm(page);
    });

    await test.step("cancel the sign-out", async () => {
      await confirmHostedSignOut(page, "cancel");
    });

    await test.step("the route is accessible again WITHOUT a credentials prompt", async () => {
      // The route cookie was already cleared when sign-out started
      // (proxy/handlers_sign_out.go), so a silent SSO round trip through the
      // still-alive hosted session is EXPECTED - asserting cookie persistence
      // would be wrong. The invariant: no credentials form blocks navigation.
      await gotoStable(page, urls.verifyHostedOld);
      await page.waitForURL((url) => url.hostname === ROUTE_HOSTNAME, {
        timeout: timeouts.long,
      });
    });

    await test.step("the same user's identity still reaches the upstream", async () => {
      await expectUpstreamSeesUser(page, urls.verifyHostedOld, user.email);
    });
  });
});
