import { test, expect } from "@playwright/test";

import { probeMcp, discoverPRM, fetchResourceMetadata } from "../mcp-client/oauth-raw.js";
import { MCP_ORIGIN } from "../mcp-client/constants.js";

// ENG-3638 §R — the 401 WWW-Authenticate challenge must carry a resource_metadata
// URI (RFC 9728 §5.1), and that document's `resource` must match the server URL.

test.describe("WWW-Authenticate challenge (ENG-3638 R)", () => {
  test("R1: 401 on /mcp carries a Bearer resource_metadata for the /mcp resource", async ({
    request,
  }) => {
    const c = await probeMcp(request, `${MCP_ORIGIN}/mcp`);
    expect(c.status).toBe(401);
    expect(c.wwwAuthenticate).toMatch(/bearer/i);
    expect(c.resourceMetadataUrl, "resource_metadata param present").toBeTruthy();
    expect(c.resourceMetadataUrl!).toContain("/.well-known/oauth-protected-resource/mcp");
  });

  test("R2/R3: root path resource_metadata has no trailing slash and no path segment", async ({
    request,
  }) => {
    const c = await probeMcp(request, `${MCP_ORIGIN}/`);
    expect(c.status).toBe(401);
    expect(c.resourceMetadataUrl).toBe(
      `${MCP_ORIGIN}/.well-known/oauth-protected-resource`,
    );
  });

  test("R4: PRM document's resource matches the /mcp server URL", async ({ request }) => {
    const { doc } = await discoverPRM(request, MCP_ORIGIN, "/mcp");
    expect(doc.resource).toBe(`${MCP_ORIGIN}/mcp`);
  });

  test("R6: resource_metadata URL from the challenge round-trips to a matching resource", async ({
    request,
  }) => {
    const c = await probeMcp(request, `${MCP_ORIGIN}/mcp`);
    expect(c.resourceMetadataUrl).toBeTruthy();
    const doc = await fetchResourceMetadata(request, c.resourceMetadataUrl!);
    expect(doc.resource).toBe(`${MCP_ORIGIN}/mcp`);
  });
});
