import { test, expect } from "@playwright/test";

import { connectWithBrowserAuth } from "../mcp-client/connect.js";
import { MCP_SERVER_URL } from "../mcp-client/constants.js";
import { testUsers } from "../../browser/fixtures/users.js";

/**
 * Negative enforcement: prove Pomerium actually protects the MCP resource, not
 * just that the happy path works.
 */

test("unauthenticated request is challenged with 401 + WWW-Authenticate", async ({ request }) => {
  // A bare MCP request with no token must be rejected by Pomerium with an OAuth
  // challenge (RFC 9728) rather than reaching the upstream.
  const res = await request.post(MCP_SERVER_URL, {
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    data: {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "probe", version: "1.0.0" },
      },
    },
    failOnStatusCode: false,
  });

  expect(res.status()).toBe(401);
  expect(res.headers()["www-authenticate"] ?? "").toMatch(/Bearer/i);
});

test("authenticated user without the admins group is denied", async ({ page }) => {
  // charlie is in the engineering group only; the MCP route requires admins.
  // The user authenticates successfully at Keycloak, but Pomerium denies access,
  // so the end-to-end connect fails. The denial must be an authorization failure
  // (403), not a setup/timeout error — otherwise this would false-pass.
  let error: unknown;
  try {
    const connected = await connectWithBrowserAuth({
      page,
      serverUrl: MCP_SERVER_URL,
      user: testUsers.charlie,
      authTimeoutMs: 25_000,
    });
    await connected.close();
  } catch (e) {
    error = e;
  }

  expect(error, "charlie must be denied access to the admins-only MCP route").toBeDefined();
  // Pomerium denies with an MCP-level "access denied" error, confirming the
  // failure is an authorization decision rather than an unrelated error.
  expect(String((error as Error)?.message ?? error)).toMatch(/access denied/i);
});
