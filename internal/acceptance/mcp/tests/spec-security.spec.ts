import { test, expect, type APIRequestContext, type Page } from "@playwright/test";

import { startCallbackServer } from "../mcp-client/callback-server.js";
import {
  discoverAS,
  registerClient,
  publicClientMetadata,
  authorizeViaBrowser,
  exchangeCode,
  pkce,
} from "../mcp-client/oauth-raw.js";
import { MCP_ORIGIN, MCP_SERVER_URL } from "../mcp-client/constants.js";
import { testUsers } from "../../browser/fixtures/users.js";

// Downstream OAuth security regressions. Per the hybrid policy, the PKCE-bypass
// check is a hard assertion (security-critical, ENG-3976); the rest are converted
// to test.fixme("ENG-####: …") if they fail against the current image.

test.describe("downstream OAuth security", () => {
  test("PKCE cannot be bypassed with an empty verifier (ENG-3976)", async ({ page, request }) => {
    // Drive a fully valid authorization first, using a real S256 challenge. The
    // AS metadata guarantees S256 is advertised, so this reliably reaches
    // Keycloak and yields a code bound to that challenge. Probing the bypass at
    // /authorize instead (empty challenge + `plain`) is unreliable: if Pomerium
    // only supports S256 it rejects the request before a code is ever issued,
    // and the security assertion below would then pass vacuously — succeeding
    // even if the /token endpoint did NOT actually verify PKCE.
    const flow = await validAuthorize(page, request, testUsers.alice);
    expect(flow.code, "a valid authorize must yield a code to attempt the bypass").toBeTruthy();

    // Invariant: a code bound to a PKCE challenge MUST NOT be redeemable with an
    // empty code_verifier. This exchange always runs, so the test can never pass
    // without actually exercising the token endpoint's PKCE check.
    const tok = await exchangeCode(request, flow.as.token_endpoint, {
      code: flow.code,
      clientId: flow.clientId,
      redirectUri: flow.redirectUri,
      codeVerifier: "",
      resource: MCP_SERVER_URL,
    });
    expect(
      tok.body.access_token,
      "empty verifier must not yield an access token (ENG-3976)",
    ).toBeFalsy();
    expect(tok.status, "empty-verifier token exchange must not return 200").not.toBe(200);
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
