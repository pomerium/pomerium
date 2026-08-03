import { test, expect } from "@playwright/test";

import { connectWithBrowserAuth } from "../mcp-client/connect.js";
import { MCP_SERVER_URL, MCP_FILTERED_URL } from "../mcp-client/constants.js";
import { testUsers } from "../../browser/fixtures/users.js";

type TextContent = { type: string; text?: string };

test.describe("MCP tool proxying + tool-level policy", () => {
  test("lists all tools and returns structured output through Pomerium", async ({ page }) => {
    const conn = await connectWithBrowserAuth({
      page,
      serverUrl: MCP_SERVER_URL,
      user: testUsers.alice,
    });
    try {
      const { tools } = await conn.client.listTools();
      expect(tools.map((t) => t.name)).toEqual(
        expect.arrayContaining(["add", "echo", "stats"]),
      );

      const echo = await conn.client.callTool({ name: "echo", arguments: { message: "hi" } });
      expect((echo.content as TextContent[])[0]?.text).toBe("hi");

      // 2025-11-25 typed tool result: the tool declares an outputSchema and
      // returns structuredContent.
      const stats = await conn.client.callTool({
        name: "stats",
        arguments: { numbers: [2, 4, 6] },
      });
      expect(stats.isError ?? false).toBe(false);
      expect(stats.structuredContent).toMatchObject({ sum: 12, count: 3, mean: 4 });
    } finally {
      await conn.close();
    }
  });

  test("invalid tool input surfaces as a tool execution error, not a protocol error (SEP-1303)", async ({
    page,
  }) => {
    const conn = await connectWithBrowserAuth({
      page,
      serverUrl: MCP_SERVER_URL,
      user: testUsers.alice,
    });
    try {
      // `add` expects numbers; passing a string should come back as isError:true
      // content (model-self-correctable) rather than a thrown JSON-RPC error.
      const res = await conn.client.callTool({
        name: "add",
        arguments: { a: "not-a-number", b: 3 },
      });
      expect(res.isError).toBe(true);
    } finally {
      await conn.close();
    }
  });

  test("tool-level policy denies a disallowed tool call (mcp_tool)", async ({ page }) => {
    // The mcp-filtered route allows admins but denies every tool except `echo`
    // (mcp_tool: not echo). Pomerium enforces this at tools/call time (matching
    // internal/mcp/e2e/mcp_test.go), so `echo` succeeds and `add` is denied.
    const conn = await connectWithBrowserAuth({
      page,
      serverUrl: MCP_FILTERED_URL,
      user: testUsers.alice,
    });
    try {
      const echo = await conn.client.callTool({ name: "echo", arguments: { message: "ok" } });
      expect((echo.content as TextContent[])[0]?.text).toBe("ok");

      // `add` is denied by policy. Assert the *reason* is a Pomerium access
      // denial — not any transport/5xx error — whether it surfaces as a thrown
      // McpError or an isError result. A bare `catch → denied = true` would pass
      // for the wrong reason (a disconnect or 500 would look like a "denial").
      let denialMessage: string | undefined;
      try {
        const res = await conn.client.callTool({ name: "add", arguments: { a: 1, b: 2 } });
        if (res.isError) {
          denialMessage = (res.content as TextContent[]).map((c) => c.text ?? "").join(" ");
        }
      } catch (err) {
        denialMessage = err instanceof Error ? err.message : String(err);
      }
      expect(denialMessage, "add must be denied on the echo-only route").toBeDefined();
      expect(denialMessage!, "denial must be a Pomerium policy decision").toMatch(/access denied/i);
    } finally {
      await conn.close();
    }
  });
});
