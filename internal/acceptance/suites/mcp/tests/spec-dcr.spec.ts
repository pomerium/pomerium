import { test, expect } from "@playwright/test";

import { discoverAS, registerClient, publicClientMetadata } from "../mcp-client/oauth-raw.js";
import { MCP_ORIGIN } from "../mcp-client/constants.js";

// Dynamic Client Registration (RFC 7591) against Pomerium's downstream AS.
// The MCP TS SDK uses DCR by default; these assert the register endpoint's
// contract directly.

const LOOPBACK_REDIRECT = "http://127.0.0.1:61234/callback";

test.describe("Dynamic Client Registration (downstream, RFC 7591)", () => {
  test("registers a public (PKCE) client and returns an opaque client_id", async ({ request }) => {
    const as = await discoverAS(request, MCP_ORIGIN);
    expect(as.registration_endpoint).toBeTruthy();

    const { status, body } = await registerClient(
      request,
      as.registration_endpoint!,
      publicClientMetadata(LOOPBACK_REDIRECT),
    );

    expect([200, 201]).toContain(status);
    expect(body?.client_id, "registration returns a client_id").toBeTruthy();
    // token_endpoint_auth_method "none" => public client, no secret issued.
    expect(body?.client_secret ?? null).toBeNull();
    expect(body?.redirect_uris as string[]).toContain(LOOPBACK_REDIRECT);
  });

  test("rejects registration metadata missing redirect_uris with 400 invalid_client_metadata", async ({
    request,
  }) => {
    const as = await discoverAS(request, MCP_ORIGIN);
    const { status, body } = await registerClient(request, as.registration_endpoint!, {
      client_name: "no-redirects",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
    expect(status).toBe(400);
    expect(String(body?.error ?? "")).toContain("invalid_client_metadata");
  });
});
