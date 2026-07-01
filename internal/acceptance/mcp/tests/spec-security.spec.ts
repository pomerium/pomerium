import { test, expect, type APIRequestContext, type Page } from "@playwright/test";

import { startCallbackServer } from "../mcp-client/callback-server.js";
import { submitLoginForm } from "../mcp-client/keycloak-login.js";
import {
  discoverAS,
  registerClient,
  publicClientMetadata,
  authorizeViaBrowser,
  exchangeCode,
  pkce,
} from "../mcp-client/oauth-raw.js";
import { MCP_ORIGIN, MCP_SERVER_URL, KEYCLOAK_HOST } from "../mcp-client/constants.js";
import { testUsers } from "../../browser/fixtures/users.js";

// Downstream OAuth security regressions. Per the hybrid policy, the PKCE-bypass
// check is a hard assertion (security-critical, ENG-3976); the rest are converted
// to test.fixme("ENG-####: …") if they fail against the current image.

test.describe("downstream OAuth security", () => {
  test("PKCE cannot be bypassed with an empty challenge/verifier (ENG-3976)", async ({
    page,
    request,
  }) => {
    const cb = await startCallbackServer();
    try {
      const as = await discoverAS(request, MCP_ORIGIN);
      const reg = await registerClient(
        request,
        as.registration_endpoint!,
        publicClientMetadata(cb.redirectUrl),
      );
      const clientId = reg.body?.client_id as string;
      expect(clientId).toBeTruthy();

      // Authorization request with an EMPTY code_challenge.
      const authUrl = new URL(as.authorization_endpoint);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("client_id", clientId);
      authUrl.searchParams.set("redirect_uri", cb.redirectUrl);
      authUrl.searchParams.set("state", "pkce-bypass");
      authUrl.searchParams.set("code_challenge", "");
      authUrl.searchParams.set("code_challenge_method", "plain");
      authUrl.searchParams.set("resource", MCP_SERVER_URL);

      await page.goto(authUrl.toString());
      const reachedKeycloak = await page
        .waitForURL((u) => u.hostname === KEYCLOAK_HOST, { timeout: 15000 })
        .then(() => true)
        .catch(() => false);

      let code: string | undefined;
      if (reachedKeycloak) {
        await submitLoginForm(page, testUsers.alice);
        code = await cb.waitForCode(15000).catch(() => undefined);
      }

      // Invariant: an empty-PKCE flow must NEVER produce a usable access token,
      // whether Pomerium rejects it at /authorize (no code issued) or at /token
      // (empty code_verifier). The final assertion runs in EVERY branch, so the
      // test can't silently pass without actually checking anything.
      let accessToken: unknown;
      let tokenStatus: number | undefined;
      if (code) {
        const tok = await exchangeCode(request, as.token_endpoint, {
          code,
          clientId,
          redirectUri: cb.redirectUrl,
          codeVerifier: "",
          resource: MCP_SERVER_URL,
        });
        accessToken = tok.body.access_token;
        tokenStatus = tok.status;
      }
      expect(accessToken, "empty PKCE must not yield an access token (ENG-3976)").toBeFalsy();
      if (tokenStatus !== undefined) {
        expect(tokenStatus, "empty-verifier token exchange must not return 200").not.toBe(200);
      }
    } finally {
      cb.close();
    }
  });

  test("authorization codes are single-use (replay rejected)", async ({ page, request }) => {
    const flow = await validAuthorize(page, request, testUsers.alice);
    const exchange = {
      code: flow.code,
      clientId: flow.clientId,
      redirectUri: flow.redirectUri,
      codeVerifier: flow.verifier,
      resource: MCP_SERVER_URL,
    };

    const first = await exchangeCode(request, flow.as.token_endpoint, exchange);
    expect(first.status).toBe(200);
    expect(first.body.access_token).toBeTruthy();

    const replay = await exchangeCode(request, flow.as.token_endpoint, exchange);
    expect(replay.status).not.toBe(200);
    expect(String(replay.body.error ?? "")).toMatch(/invalid_grant/i);
  });

  test("loopback redirect URI is matched ignoring port (OAuth 2.1 / RFC 8252) (ENG-3857)", async ({
    page,
    request,
  }) => {
    const cbReg = await startCallbackServer(); // port registered with the client
    const cbUse = await startCallbackServer(); // different loopback port at authorize time
    try {
      const as = await discoverAS(request, MCP_ORIGIN);
      const reg = await registerClient(
        request,
        as.registration_endpoint!,
        publicClientMetadata(cbReg.redirectUrl),
      );
      const clientId = reg.body?.client_id as string;
      const { verifier, challenge } = pkce();

      const code = await authorizeViaBrowser({
        page,
        asMeta: as,
        clientId,
        redirectUri: cbUse.redirectUrl,
        user: testUsers.alice,
        codeChallenge: challenge,
        resource: MCP_SERVER_URL,
        waitForCode: () => cbUse.waitForCode(15000),
      }).catch(() => undefined);

      expect(code, "authorize with a different loopback port should still succeed").toBeTruthy();

      const tok = await exchangeCode(request, as.token_endpoint, {
        code: code!,
        clientId,
        redirectUri: cbUse.redirectUrl,
        codeVerifier: verifier,
        resource: MCP_SERVER_URL,
      });
      expect(tok.status).toBe(200);
      expect(tok.body.access_token).toBeTruthy();
    } finally {
      cbReg.close();
      cbUse.close();
    }
  });

  // ENG-3982: createTokenResponse can emit a negative expires_in when a session
  // has ticked past expiry. Reproducing that needs a session at/after expiry
  // (timing/clustered), which a fresh container flow can't reliably create.
  test.fixme(
    "ENG-3982: token endpoint never returns a negative expires_in (needs expired-session timing)",
    () => {},
  );
});

interface AuthorizedFlow {
  as: Awaited<ReturnType<typeof discoverAS>>;
  clientId: string;
  code: string;
  verifier: string;
  redirectUri: string;
}

async function validAuthorize(
  page: Page,
  request: APIRequestContext,
  user: (typeof testUsers)[string],
): Promise<AuthorizedFlow> {
  const cb = await startCallbackServer();
  try {
    const as = await discoverAS(request, MCP_ORIGIN);
    const reg = await registerClient(
      request,
      as.registration_endpoint!,
      publicClientMetadata(cb.redirectUrl),
    );
    const clientId = reg.body?.client_id as string;
    const { verifier, challenge } = pkce();
    const code = await authorizeViaBrowser({
      page,
      asMeta: as,
      clientId,
      redirectUri: cb.redirectUrl,
      user,
      codeChallenge: challenge,
      resource: MCP_SERVER_URL,
      waitForCode: () => cb.waitForCode(20000),
    });
    return { as, clientId, code, verifier, redirectUri: cb.redirectUrl };
  } finally {
    cb.close();
  }
}
