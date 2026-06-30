// The MCP endpoint the client connects to. This is the Pomerium MCP server route
// (https), which proxies to the upstream MCP server at http://mcp-upstream:8080/mcp.
export const MCP_SERVER_URL =
  process.env.POMERIUM_MCP_URL ?? "https://mcp.localhost.pomerium.io:8443/mcp";

// Identifies this test client to both the OAuth authorization server (DCR
// client_name) and the MCP protocol (clientInfo name).
export const CLIENT_NAME = "pomerium-mcp-e2e-client";
