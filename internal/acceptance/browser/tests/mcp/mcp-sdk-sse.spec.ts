/**
 * MCP SSE Transport Tests
 *
 * Priority: P1
 * Validates: MCP SSE transport works through Pomerium with the
 *            OAuth 2.1 authorization flow.
 *
 * Architecture:
 *   Uses page.evaluate() with fetch() ReadableStream (not EventSource,
 *   which cannot set custom headers) to open an SSE connection and
 *   exchange JSON-RPC messages through the /messages endpoint.
 */

import { test, expect } from "@playwright/test";
import { clearAuthState } from "../../helpers/authn-flow.js";
import {
  acquireMcpToken,
  mcpSseConnect,
  mcpSseSession,
} from "../../helpers/mcp.js";
import { testUsers } from "../../fixtures/users.js";
import { mcpUrls, buildUrl } from "../../fixtures/test-data.js";

test.describe("MCP SSE Transport through Pomerium", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  // -------------------------------------------------------------------------
  // Auth gating
  // -------------------------------------------------------------------------

  test("unauthenticated SSE request should be rejected", async ({ page }) => {
    const url = buildUrl(mcpUrls.server, "/sse");
    const response = await page.request.get(url, {
      headers: { Accept: "text/event-stream" },
      ignoreHTTPSErrors: true,
    });

    // Pomerium should reject with 401 or redirect (302)
    expect([401, 302]).toContain(response.status());
  });

  // -------------------------------------------------------------------------
  // SSE connection
  // -------------------------------------------------------------------------

  test("authenticated SSE connection should receive endpoint event", async ({
    page,
  }) => {
    const user = testUsers.alice;
    const { tokens } = await acquireMcpToken(page, user);

    const result = await mcpSseConnect(page, tokens.access_token);

    expect(result.error).toBeUndefined();
    expect(result.endpointUrl).toBeTruthy();
    expect(result.endpointUrl).toContain("/messages?sessionId=");
  });

  // -------------------------------------------------------------------------
  // Full SSE session: initialize + tools/list
  // -------------------------------------------------------------------------

  test("tools/list via SSE should return echo, add, get_time", async ({
    page,
  }) => {
    const user = testUsers.alice;
    const { tokens } = await acquireMcpToken(page, user);

    const result = await mcpSseSession(page, tokens.access_token, [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "e2e-sse", version: "1.0.0" },
        },
      },
      {
        jsonrpc: "2.0",
        method: "notifications/initialized",
      },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
      },
    ]);

    expect(result.error).toBeUndefined();
    // Should have 2 responses: initialize (id:1) and tools/list (id:2)
    // Notification (no id) doesn't produce a response
    expect(result.responses.length).toBe(2);

    // Check initialize response
    const initBody = result.responses[0] as {
      result?: { serverInfo?: { name?: string } };
    };
    expect(initBody.result).toBeDefined();
    expect(initBody.result!.serverInfo!.name).toBe("pomerium-test-server");

    // Check tools/list response
    const toolsBody = result.responses[1] as {
      result?: { tools?: Array<{ name: string }> };
    };
    expect(toolsBody.result).toBeDefined();
    expect(toolsBody.result!.tools).toBeInstanceOf(Array);

    const toolNames = toolsBody.result!.tools!.map((t) => t.name);
    expect(toolNames).toContain("echo");
    expect(toolNames).toContain("add");
    expect(toolNames).toContain("get_time");
  });
});
