// The MCP endpoint the client connects to. This is the Pomerium MCP server route
// (https), which proxies to the upstream MCP server at http://mcp-upstream:8080/mcp.
export const MCP_SERVER_URL =
  process.env.POMERIUM_MCP_URL ?? "https://mcp.localhost.pomerium.io:8443/mcp";

// Origin of the MCP server route (for /.well-known/* metadata fetches).
export const MCP_ORIGIN = "https://mcp.localhost.pomerium.io:8443";

// A second MCP route whose policy allows only the `echo` tool (mcp_tool: not echo).
// Used by spec-tools to verify tool-level policy filtering.
export const MCP_FILTERED_URL = "https://mcp-filtered.localhost.pomerium.io:8443/mcp";

// Identifies this test client to both the OAuth authorization server (DCR
// client_name) and the MCP protocol (clientInfo name).
export const CLIENT_NAME = "pomerium-mcp-e2e-client";

// Hostname of the Keycloak IdP the browser is redirected to during sign-in.
// The authorization leg lands here before Pomerium mints a session.
export const KEYCLOAK_HOST = "keycloak.localhost.pomerium.io";
