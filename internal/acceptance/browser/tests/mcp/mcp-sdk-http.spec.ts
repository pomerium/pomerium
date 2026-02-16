/**
 * MCP Streamable HTTP Transport Tests
 *
 * Priority: P0
 * Validates: MCP Streamable HTTP transport works through Pomerium's
 *            OAuth 2.1 authorization flow (register → authorize → token → call).
 *
 * Architecture:
 *   Playwright registers a dynamic OAuth client, navigates the browser
 *   through Keycloak login to obtain an MCP Bearer token, then uses
 *   that token for JSON-RPC requests to the upstream MCP server.
 */

import { test, expect } from "@playwright/test";
import { clearAuthState } from "../../helpers/authn-flow.js";
import {
  acquireMcpToken,
  registerMcpClient,
  mcpInitialize,
  mcpInitializedNotify,
  mcpToolsList,
  mcpToolsCall,
} from "../../helpers/mcp.js";
import { testUsers } from "../../fixtures/users.js";
import { mcpUrls, mcpPaths, buildUrl } from "../../fixtures/test-data.js";

test.describe("MCP Streamable HTTP Transport through Pomerium", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  // -------------------------------------------------------------------------
  // Auth discovery & gating
  // -------------------------------------------------------------------------

  test("OAuth metadata endpoint should be publicly accessible", async ({
    page,
  }) => {
    const url = buildUrl(mcpUrls.server, mcpPaths.oauthMetadata);
    const response = await page.request.get(url, {
      ignoreHTTPSErrors: true,
    });

    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.authorization_endpoint).toContain("/.pomerium/mcp/authorize");
    expect(body.token_endpoint).toContain("/.pomerium/mcp/token");
    expect(body.registration_endpoint).toContain("/.pomerium/mcp/register");
    expect(body.code_challenge_methods_supported).toContain("S256");
  });

  test("dynamic client registration should succeed", async ({ page }) => {
    const client = await registerMcpClient(page);

    expect(client.client_id).toBeTruthy();
    expect(client.redirect_uris[0]).toContain("/oauth-test-callback");
    expect(client.token_endpoint_auth_method).toBe("none");
  });

  test("unauthenticated request to MCP route should be rejected", async ({
    page,
  }) => {
    const url = buildUrl(mcpUrls.server, "/mcp");
    const response = await page.request.post(url, {
      data: {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "e2e-test", version: "1.0.0" },
        },
      },
      headers: { "Content-Type": "application/json" },
      ignoreHTTPSErrors: true,
    });

    // Pomerium should reject with 401 or redirect (302)
    expect([401, 302]).toContain(response.status());
  });

  // -------------------------------------------------------------------------
  // Full OAuth flow → Streamable HTTP
  // -------------------------------------------------------------------------

  test("authenticated initialize should succeed", async ({ page }) => {
    const user = testUsers.alice;
    const { tokens } = await acquireMcpToken(page, user);

    expect(tokens.access_token).toBeTruthy();
    expect(tokens.token_type).toBe("Bearer");

    const result = await mcpInitialize(page, tokens.access_token);
    expect(result.status).toBe(200);

    const body = result.body as {
      result?: { protocolVersion?: string; serverInfo?: { name?: string } };
    };
    expect(body.result).toBeDefined();
    expect(body.result!.protocolVersion).toBeDefined();
    expect(body.result!.serverInfo).toBeDefined();
    expect(body.result!.serverInfo!.name).toBe("pomerium-test-server");
  });

  test("tools/list should return echo, add, get_time", async ({ page }) => {
    const user = testUsers.alice;
    const { tokens } = await acquireMcpToken(page, user);

    // Initialize first
    await mcpInitialize(page, tokens.access_token);
    await mcpInitializedNotify(page, tokens.access_token);

    // List tools
    const result = await mcpToolsList(page, tokens.access_token);
    expect(result.status).toBe(200);

    const body = result.body as {
      result?: { tools?: Array<{ name: string }> };
    };
    expect(body.result).toBeDefined();
    expect(body.result!.tools).toBeInstanceOf(Array);

    const toolNames = body.result!.tools!.map((t) => t.name);
    expect(toolNames).toContain("echo");
    expect(toolNames).toContain("add");
    expect(toolNames).toContain("get_time");
  });

  test("tool call (echo) should return correct response", async ({
    page,
  }) => {
    const user = testUsers.alice;
    const { tokens } = await acquireMcpToken(page, user);

    await mcpInitialize(page, tokens.access_token);

    const result = await mcpToolsCall(page, tokens.access_token, "echo", {
      message: "hello from e2e test",
    });
    expect(result.status).toBe(200);

    const body = result.body as {
      result?: { content?: Array<{ text?: string }> };
    };
    expect(body.result).toBeDefined();
    expect(body.result!.content).toBeInstanceOf(Array);
    expect(body.result!.content![0].text).toContain("hello from e2e test");
  });

  test("tool call (add) should return correct sum", async ({ page }) => {
    const user = testUsers.alice;
    const { tokens } = await acquireMcpToken(page, user);

    await mcpInitialize(page, tokens.access_token);

    const result = await mcpToolsCall(page, tokens.access_token, "add", {
      a: 17,
      b: 25,
    });
    expect(result.status).toBe(200);

    const body = result.body as {
      result?: { content?: Array<{ text?: string }> };
    };
    expect(body.result!.content![0].text).toBe("42");
  });

  test("tool call (get_time) should return an ISO timestamp", async ({
    page,
  }) => {
    const user = testUsers.alice;
    const { tokens } = await acquireMcpToken(page, user);

    await mcpInitialize(page, tokens.access_token);

    const result = await mcpToolsCall(
      page,
      tokens.access_token,
      "get_time",
      {}
    );
    expect(result.status).toBe(200);

    const body = result.body as {
      result?: { content?: Array<{ text?: string }> };
    };
    const timestamp = body.result!.content![0].text!;
    // Verify it's a valid ISO 8601 timestamp
    expect(new Date(timestamp).toISOString()).toBe(timestamp);
  });
});
