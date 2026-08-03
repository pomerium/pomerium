import { test, expect } from "@playwright/test";

import { discoverAS, discoverPRM } from "../mcp-client/oauth-raw.js";
import { MCP_ORIGIN } from "../mcp-client/constants.js";

// MCP 2025-11-25 §Authorization: an MCP server MUST expose Protected Resource
// Metadata (RFC 9728) and its authorization server MUST be discoverable (RFC 8414
// / OIDC). These assert the shape of the metadata Pomerium (the downstream AS)
// serves against the official image.

test.describe("downstream authorization metadata (MCP 2025-11-25)", () => {
  test("protected resource metadata (RFC 9728) is well-formed", async ({ request }) => {
    const { doc } = await discoverPRM(request, MCP_ORIGIN, "/mcp");
    expect(doc.resource, "PRM MUST carry a resource identifier").toBeTruthy();
    expect(
      doc.authorization_servers ?? [],
      "PRM MUST list at least one authorization server",
    ).not.toHaveLength(0);
    expect(doc.bearer_methods_supported ?? []).toContain("header");
  });

  test("authorization server metadata advertises the required 2025-11-25 capabilities", async ({
    request,
  }) => {
    const md = await discoverAS(request, MCP_ORIGIN);

    expect(md.issuer, "issuer is REQUIRED").toBeTruthy();
    expect(md.authorization_endpoint).toContain("/.pomerium/mcp/authorize");
    expect(md.token_endpoint).toContain("/.pomerium/mcp/token");
    expect(md.registration_endpoint, "DCR endpoint advertised").toContain(
      "/.pomerium/mcp/register",
    );
    expect(md.response_types_supported ?? []).toContain("code");
    expect(md.grant_types_supported ?? []).toEqual(
      expect.arrayContaining(["authorization_code", "refresh_token"]),
    );
    // Spec: clients MUST refuse to proceed if code_challenge_methods_supported is
    // absent — so the AS MUST advertise S256.
    expect(md.code_challenge_methods_supported ?? []).toContain("S256");
    expect(md.token_endpoint_auth_methods_supported ?? []).toContain("none");
    // CIMD is the recommended registration mechanism in 2025-11-25; Pomerium
    // advertises support for it.
    expect(md.client_id_metadata_document_supported).toBe(true);
  });

  test("PRM's authorization_servers points back at the AS issuer", async ({ request }) => {
    const md = await discoverAS(request, MCP_ORIGIN);
    const { doc } = await discoverPRM(request, MCP_ORIGIN, "/mcp");
    expect(doc.authorization_servers ?? []).toContain(md.issuer);
  });
});
