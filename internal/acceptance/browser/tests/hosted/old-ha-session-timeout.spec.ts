/**
 * Old Hosted Authenticate (stateless flow) - Session Timeout Test
 *
 * Notion: QA -> Test Plans -> Core Test Plan -> Authentication -> Hosted
 *         Authenticate -> "HA.Session Timeout".
 *
 * In the stateless flow session refresh is DISABLED, so cookie_expire is a
 * hard deadline. The instance under test shortens it to 90s (the QA plan uses
 * 2m; the behavior is identical) so this test completes in ~2 minutes.
 *
 * Silent-SSO caveat: after expiry the HOSTED session may still be alive, so
 * the next request may re-authenticate without showing the credentials form.
 * The hard assertion is therefore the forced re-auth ROUND TRIP through the
 * hosted /.pomerium/sign_in - form visibility is handled either way.
 *
 * Gated on HOSTED_E2E=1 + HOSTED_TEST_EMAIL/PASSWORD (real hosted account).
 */

import { test, expect } from "@playwright/test";
import { urls, paths, timeouts } from "../../fixtures/test-data.js";
import { sleep } from "../../helpers/wait.js";
import {
  HOSTED_HOSTNAME,
  completeHostedLoginIfFormShown,
  expectUpstreamSeesUser,
  loginViaHosted,
  requireHostedUser,
  skipUnlessHostedE2E,
  trackRequests,
} from "../../helpers/hosted.js";

const ROUTE_HOSTNAME = new URL(urls.verifyHostedOld).hostname;

test.describe("Old Hosted Authenticate: session timeout", () => {
  skipUnlessHostedE2E();

  test("O5: after cookie_expire elapses the next request forces a re-auth round trip", async ({
    page,
  }) => {
    // Route: https://verify-hosted-old.localhost.pomerium.io:8445 -> http://upstream:8000
    // Config: config-hosted-old.yaml (stateless flow, cookie_expire: 90s -
    //         hard deadline, no session refresh in stateless mode)
    test.setTimeout(240_000); // login + 90s cookie_expire + re-auth round trip
    const user = requireHostedUser();

    const loginAt = await test.step("log in via the hosted authenticate", async () => {
      await loginViaHosted(page, { targetUrl: urls.verifyHostedOld, user });
      return Date.now();
    });

    await test.step("immediately after login the route is served WITHOUT a hosted round trip", async () => {
      const hostedRequests = trackRequests(page, (url) => url.hostname === HOSTED_HOSTNAME);
      const response = await page.goto(`${urls.verifyHostedOld}/json`, {
        waitUntil: "domcontentloaded",
      });
      hostedRequests.dispose();
      expect(response, "navigation should produce a response").not.toBeNull();
      expect(response!.status()).toBe(200);
      expect(
        hostedRequests.urls(),
        "a fresh session must not round-trip through the hosted service"
      ).toEqual([]);
    });

    await test.step("wait until the session cookie has expired", async () => {
      // Sleep out the configured lifetime, then poll for the observable
      // signal (the sign-in redirect) instead of guessing a fixed buffer.
      // Safe in stateless mode: no refresh, so polling cannot extend the
      // session; this is the same check the next step relies on.
      const elapsed = Date.now() - loginAt;
      await sleep(Math.max(timeouts.hostedCookieExpire - elapsed, 0));
      await expect
        .poll(
          async () => {
            const response = await page.request.get(`${urls.verifyHostedOld}${paths.user}`, {
              ignoreHTTPSErrors: true,
              maxRedirects: 0,
            });
            return response.status();
          },
          { timeout: 30_000, message: "session should expire into a sign-in redirect" }
        )
        .toBe(302);
    });

    await test.step("the next request is forced back through the hosted sign-in", async () => {
      const signInHop = page.waitForRequest(
        (req) => req.url().startsWith(`${urls.hostedAuthenticate}${paths.signIn}`),
        { timeout: timeouts.long }
      );
      await page.goto(urls.verifyHostedOld, { waitUntil: "domcontentloaded" });
      // Tolerates both outcomes: credentials form shown (hosted session also
      // expired) or silent SSO completion (hosted session still alive).
      await completeHostedLoginIfFormShown(page, ROUTE_HOSTNAME, user);
      await signInHop;
    });

    await test.step("access after re-authentication is intact", async () => {
      await expectUpstreamSeesUser(page, urls.verifyHostedOld, user.email);
    });
  });
});
