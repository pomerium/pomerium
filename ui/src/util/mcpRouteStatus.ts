// Status of a single MCP server as returned by the /.pomerium/mcp/routes*
// endpoints.
export type MCPServerStatus = {
  url: string;
  connected?: boolean;
  token_expires_at?: string;
  refresh_token_available?: boolean;
};

const hostnameOf = (url: string): string | undefined => {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
};

// findServerStatus returns the entry for a portal route in a routes listing.
// The listing's url has the MCP server path appended to the route's `from`, so
// entries are matched by hostname, which is also how the server looks routes up.
export const findServerStatus = (
  servers: MCPServerStatus[] | undefined,
  routeFrom: string,
): MCPServerStatus | undefined => {
  const hostname = hostnameOf(routeFrom);
  if (!hostname) {
    return undefined;
  }
  return servers?.find((s) => hostnameOf(s.url) === hostname);
};

// canRefresh reports whether a connected route can be refreshed: without a
// stored refresh token the Refresh action can only fail.
export const canRefresh = (s: MCPServerStatus): boolean =>
  !!s.refresh_token_available;

// refreshTokenCaption describes the stored refresh token. A missing one is
// flagged as an error: the route will need reconnecting once the access token
// expires.
export const refreshTokenCaption = (
  s: MCPServerStatus,
): { text: string; color: "textSecondary" | "error" } => ({
  text: `Refresh token: ${s.refresh_token_available ? "available" : "not available"}`,
  color: s.refresh_token_available ? "textSecondary" : "error",
});
