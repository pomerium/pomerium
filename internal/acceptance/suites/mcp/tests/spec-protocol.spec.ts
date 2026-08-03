import { test, expect } from "@playwright/test";

import { connectWithBrowserAuth } from "../mcp-client/connect.js";
import { MCP_SERVER_URL } from "../mcp-client/constants.js";
import { testUsers } from "../../browser/fixtures/users.js";

// MCP 2025-11-25 protocol version + Streamable HTTP transport behavior, observed
// through Pomerium against the official image.

test.describe("MCP protocol version + transport (2025-11-25)", () => {
  test("client and server negotiate protocol version 2025-11-25 through Pomerium", async ({
    page,
  }) => {
    const conn = await connectWithBrowserAuth({
      page,
      serverUrl: MCP_SERVER_URL,
      user: testUsers.alice,
    });
    try {
      expect(conn.transport.protocolVersion).toBe("2025-11-25");
      // Post-initialize requests carry the MCP-Protocol-Version header; a
      // successful tools/list proves Pomerium forwards it (it is an allowed
      // header on the MCP route) and does not downgrade the session.
      const { tools } = await conn.client.listTools();
      expect(tools.length).toBeGreaterThan(0);
    } finally {
      await conn.close();
    }
  });

  // MCP 2025-11-25 requires MCP *servers* to reject invalid Origin headers with
  // 403 (DNS-rebinding protection). That is the upstream MCP server's job (SDK
  // `allowedOrigins`), not the proxy's; our stateless test upstream leaves it
  // disabled, so this is intentionally out of scope for the Pomerium suite.
  test.skip("invalid Origin -> 403 is the MCP server's responsibility, not the proxy's", () => {});
});
