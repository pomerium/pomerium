/**
 * Old Hosted Authenticate (stateless flow) - Login Tests
 *
 * Notion: QA -> Test Plans -> Core Test Plan -> Authentication -> Hosted
 *         Authenticate -> "HA.Email-password.positive" /
 *         "HA.Email-password.negative".
 *
 * Flow under test: authenticate_service_url: https://authenticate.pomerium.app
 * switches Pomerium to the STATELESS authenticate flow - no local authenticate
 * service; the sign-in UI lives at the hosted service and the whole exchange
 * travels via browser redirects with HPKE-sealed query params (k & q).
 *
 * "HA.Google single-sign.positive" is intentionally NOT automated: a real
 * Google login cannot be driven by automation (bot detection, 2FA, ToS) - it
 * stays a manual test case.
 *
 * Gated on HOSTED_E2E=1 (`make test-suite-hosted`). The positive test
 * additionally needs HOSTED_TEST_EMAIL/PASSWORD. The live UI diverges from the
 * QA plan's expected wording - see the live-UI facts in helpers/hosted.ts.
 */

import { test, expect } from "@playwright/test";
import { urls, paths, timeouts } from "../../fixtures/test-data.js";
import {
  expectEmptyFieldsBlocked,
  expectInvalidCredentialsError,
  expectSessionCookie,
  expectSignInRedirect,
  expectUpstreamSeesUser,
  loginViaHosted,
  randomInvalidEmail,
  requireHostedUser,
  skipUnlessHostedE2E,
  submitHostedLoginForm,
  waitForHostedSignInPage,
} from "../../helpers/hosted.js";

test.describe("Old Hosted Authenticate: login (stateless flow)", () => {
  skipUnlessHostedE2E();

  test("sign-in redirect goes to the hosted /.pomerium/sign_in with exactly the HPKE pair k & q", async ({
    page,
  }) => {
    // Route: https://verify-hosted-old.localhost.pomerium.io:8445 -> http://upstream:8000
    // Config: authenticate_service_url: https://authenticate.pomerium.app,
    //         no idp_* settings, cookie_expire: 90s (config-hosted-old.yaml)

    const location = await test.step("unauthenticated request is redirected to the hosted sign-in", async () => {
      return expectSignInRedirect(page, urls.verifyHostedOld);
    });

    await test.step("redirect target is the cloud authenticate service", () => {
      expect(location.origin).toBe(urls.hostedAuthenticate);
      expect(location.pathname).toBe(paths.signIn);
    });

    await test.step("query carries exactly the HPKE pair: k (sender key) and q (sealed params)", () => {
      expect([...location.searchParams.keys()].sort()).toEqual(["k", "q"]);
      expect(
        location.searchParams.get("k"),
        "k is a 32-byte X25519 public key, base64url"
      ).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(
        location.searchParams.get("q"),
        "q is the HPKE-sealed query string"
      ).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });

  test("O1: valid credentials at the hosted authenticate grant access to the route", async ({
    page,
  }) => {
    // Route: https://verify-hosted-old.localhost.pomerium.io:8445 -> http://upstream:8000 (pomerium/verify)
    // Config: config-hosted-old.yaml (stateless flow, pass_identity_headers,
    //         jwt_claims_headers X-Pomerium-Claim-Email)
    const user = requireHostedUser();

    const callback = page.waitForRequest(
      (req) => req.url().startsWith(`${urls.verifyHostedOld}/.pomerium/callback`),
      { timeout: timeouts.long }
    );

    await test.step("open the protected route and sign in at the hosted authenticate", async () => {
      await loginViaHosted(page, { targetUrl: urls.verifyHostedOld, user });
    });

    await test.step("the stateless flow returned through /.pomerium/callback/ on the route domain", async () => {
      await callback;
    });

    await test.step("a Pomerium session cookie was issued for the route domain", async () => {
      await expectSessionCookie(page, urls.verifyHostedOld);
    });

    await test.step("the upstream receives the authenticated identity header", async () => {
      await expectUpstreamSeesUser(page, urls.verifyHostedOld, user.email);
    });
  });

  test("O2: invalid credentials show a rejection error and grant no access", async ({
    page,
  }) => {
    // Route: https://verify-hosted-old.localhost.pomerium.io:8445 -> http://upstream:8000
    // Config: config-hosted-old.yaml (stateless flow)
    // Uses a random fake account - never the real one (no lockout risk).

    await test.step("reach the hosted sign-in form from the protected route", async () => {
      await page.goto(urls.verifyHostedOld, { waitUntil: "domcontentloaded" });
      await waitForHostedSignInPage(page);
    });

    await test.step("bogus credentials are rejected with a visible error", async () => {
      await submitHostedLoginForm(page, {
        email: randomInvalidEmail(),
        password: "wrong-password-12345",
      });
      await expectInvalidCredentialsError(page);
    });

    await test.step("no session was granted on the route", async () => {
      await expectSignInRedirect(page, urls.verifyHostedOld);
    });
  });

  test("O2: empty credentials cannot be submitted and grant no access", async ({ page }) => {
    // Route: https://verify-hosted-old.localhost.pomerium.io:8445 -> http://upstream:8000
    // Config: config-hosted-old.yaml (stateless flow)

    await test.step("reach the hosted sign-in form from the protected route", async () => {
      await page.goto(urls.verifyHostedOld, { waitUntil: "domcontentloaded" });
      await waitForHostedSignInPage(page);
    });

    await test.step("submission is blocked while fields are empty or partial", async () => {
      await expectEmptyFieldsBlocked(page);
    });

    await test.step("no session was granted on the route", async () => {
      await expectSignInRedirect(page, urls.verifyHostedOld);
    });
  });
});
