import { test, expect } from "@playwright/test";

import { connectWithBrowserAuth } from "../mcp-client/connect.js";
import { MCP_SERVER_URL } from "../mcp-client/constants.js";
import { testUsers } from "../../browser/fixtures/users.js";

/**
 * Full happy-path: a real MCP TypeScript SDK client connects to an upstream MCP
 * server fronted by Pomerium, authenticating an authorized user (alice, in the
 * admins group) via a real Keycloak browser sign-in, then lists and calls a tool.
 */
test("authorized user lists and calls MCP tools through Pomerium", async ({ page }) => {
  const { client, close } = await connectWithBrowserAuth({
    page,
    serverUrl: MCP_SERVER_URL,
    user: testUsers.alice,
  });

  try {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain("add");

    // Acceptance criterion: the call must succeed (not an error result) and
    // return exactly the expected value through Pomerium. Anything else fails
    // the test, and the run exits non-zero.
    const result = await client.callTool({ name: "add", arguments: { a: 2, b: 3 } });
    expect(result.isError ?? false, "the MCP tool call returned an error result").toBe(false);
    const content = result.content as Array<{ type: string; text?: string }>;
    const text = content.find((c) => c.type === "text")?.text;
    expect(text, "add(2, 3) must return exactly 5 through Pomerium").toBe("5");
  } finally {
    await close();
  }
});
