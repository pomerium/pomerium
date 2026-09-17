/**
 * New Hosted Authenticate (Hosted IdP) - Login Tests
 *
 * Notion: QA -> Test Plans -> Core Test Plan -> Authentication ->
 *         New Hosted Authenticate (Hosted IdP) -> "New HA.Log in. positive" /
 *         "New HA.Log in.negative".
 *
 * Flow under test: idp_provider "hosted" - the LOCAL authenticate service uses
 * https://authenticate.pomerium.app as its OIDC identity provider with DERIVED
 * client credentials (client_id = authenticate_service_url, EdDSA signing key
 * = HKDF(shared_secret); no idp_client_id/secret configured).
 *
 * Gated on HOSTED_E2E=1 (`make test-suite-hosted`) - talks to the REAL cloud
 * service. Positive tests additionally need HOSTED_TEST_EMAIL/PASSWORD.
 * The live UI diverges from the QA plan's expected wording - see the live-UI
 * facts in helpers/hosted.ts.
 */

import { test, expect } from "@playwright/test";
import { urls, paths, timeouts } from "../../fixtures/test-data.js";
import {
  decodeCompactJws,
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

test.describe("New Hosted Authenticate: login", () => {
  skipUnlessHostedE2E();

  test("sign-in redirects to the hosted authorization endpoint with a signed request object", async ({
    page,
  }) => {
    // Route: https://verify-hosted.localhost.pomerium.io:8444 -> http://upstream:8000
    // Config: authenticate_service_url = local :8444, idp_provider: hosted,
    //         idp_provider_url: https://authenticate.pomerium.app (config-hosted-new.yaml)

    const authorizeRequest = await test.step("unauthenticated visit is redirected to the hosted /oidc/auth", async () => {
      const captured = page.waitForRequest(
        (req) => req.url().startsWith(`${urls.hostedAuthenticate}/oidc/auth`),
        { timeout: timeouts.long }
      );
      // paths.user requires login, so it triggers the whole redirect chain
      // without touching the upstream.
      await page.goto(`${urls.verifyHostedNew}${paths.user}`, {
        waitUntil: "domcontentloaded",
      });
      return new URL((await captured).url());
    });

    await test.step("authorization request carries exactly one query param: request", () => {
      expect([...authorizeRequest.searchParams.keys()]).toEqual(["request"]);
    });

    const payload = await test.step("request param is a compact EdDSA JWS with an embedded Ed25519 JWK", () => {
      const decoded = decodeCompactJws(authorizeRequest.searchParams.get("request")!);
      expect(decoded.header.alg, "request object must be EdDSA-signed").toBe("EdDSA");
      expect(decoded.header.typ).toBe("JWT");
      const jwk = decoded.header.jwk as Record<string, unknown>;
      expect(jwk.kty, "embedded JWK must be an Ed25519 key").toBe("OKP");
      expect(jwk.crv).toBe("Ed25519");
      return decoded.payload;
    });

    await test.step("JWS claims identify this Pomerium via its derived client credentials", () => {
      expect(payload.response_type).toBe("code");
      expect(payload.client_id, "client_id is the authenticate service URL").toBe(
        urls.authenticateHostedNew
      );
      expect(payload.redirect_uri).toBe(`${urls.authenticateHostedNew}${paths.oauth2Callback}`);
      expect(payload.scope).toBe("openid profile email offline_access");
      expect(payload.iss, "iss equals the derived client_id").toBe(payload.client_id);
      expect(payload.aud, "aud is the hosted provider URL").toBe(urls.hostedAuthenticate);
      expect(payload.state, "an opaque state must be present").toBeTruthy();
      expect(String(payload.pomerium_version).trim().length).toBeGreaterThan(0);
      expect(Number(payload.exp)).toBeGreaterThan(Number(payload.iat));
      // The live hosted discovery does not advertise PKCE.
      expect(payload).not.toHaveProperty("code_challenge");
    });
  });

  test("N1: valid hosted-IdP credentials grant access to the route", async ({ page }) => {
    // Route: https://verify-hosted.localhost.pomerium.io:8444 -> http://upstream:8000 (pomerium/verify)
    // Config: config-hosted-new.yaml (idp_provider: hosted, pass_identity_headers,
    //         jwt_claims_headers X-Pomerium-Claim-Email)
    const user = requireHostedUser();

    await test.step("open the protected route and sign in at the hosted IdP", async () => {
      await loginViaHosted(page, { targetUrl: urls.verifyHostedNew, user });
    });

    await test.step("a Pomerium session cookie was issued for the route domain", async () => {
      await expectSessionCookie(page, urls.verifyHostedNew);
    });

    await test.step("the upstream receives the authenticated identity header", async () => {
      await expectUpstreamSeesUser(page, urls.verifyHostedNew, user.email);
    });
  });

  test("N2: invalid credentials show a rejection error and grant no access", async ({
    page,
  }) => {
    // Route: https://verify-hosted.localhost.pomerium.io:8444 -> http://upstream:8000
    // Config: config-hosted-new.yaml (idp_provider: hosted)
    // Uses a random fake account - never the real one (no lockout risk).

    await test.step("reach the hosted sign-in form from the protected route", async () => {
      await page.goto(urls.verifyHostedNew, { waitUntil: "domcontentloaded" });
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
      await expectSignInRedirect(page, urls.verifyHostedNew);
    });
  });

  test("N2: empty credentials cannot be submitted and grant no access", async ({ page }) => {
    // Route: https://verify-hosted.localhost.pomerium.io:8444 -> http://upstream:8000
    // Config: config-hosted-new.yaml (idp_provider: hosted)

    await test.step("reach the hosted sign-in form from the protected route", async () => {
      await page.goto(urls.verifyHostedNew, { waitUntil: "domcontentloaded" });
      await waitForHostedSignInPage(page);
    });

    await test.step("submission is blocked while fields are empty or partial", async () => {
      await expectEmptyFieldsBlocked(page);
    });

    await test.step("no session was granted on the route", async () => {
      await expectSignInRedirect(page, urls.verifyHostedNew);
    });
  });
});
