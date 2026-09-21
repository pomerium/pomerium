import {
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  CardHeader,
  Chip,
  Typography,
} from "@mui/material";
import type { FC } from "react";
import React, { useState } from "react";
import { Wifi, WifiOff } from "react-feather";

import type { Route } from "../types";

// Official MCP logo icon (3 interweaving paths from the Model Context Protocol logo)
// on a circular white background.
const mcpLogoDataURI =
  "data:image/svg+xml," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">' +
      '<circle cx="100" cy="100" r="100" fill="#fff"/>' +
      '<g transform="translate(27,5) scale(0.95)">' +
      '<path d="M25 97.8528L92.8822 29.9706C102.255 20.598 117.451 20.598 126.823 29.9706V29.9706C136.196 39.3431 136.196 54.5391 126.823 63.9117L75.5581 115.177" stroke="#000" stroke-width="12" stroke-linecap="round" fill="none"/>' +
      '<path d="M76.2652 114.47L126.823 63.9117C136.196 54.5391 151.392 54.5391 160.765 63.9117L161.118 64.2652C170.491 73.6378 170.491 88.8338 161.118 98.2063L99.7248 159.6C96.6006 162.724 96.6006 167.789 99.7248 170.913L112.331 183.52" stroke="#000" stroke-width="12" stroke-linecap="round" fill="none"/>' +
      '<path d="M109.853 46.9411L59.6482 97.1457C50.2756 106.518 50.2756 121.714 59.6482 131.087V131.087C69.0208 140.459 84.2167 140.459 93.5893 131.087L143.794 80.8822" stroke="#000" stroke-width="12" stroke-linecap="round" fill="none"/>' +
      "</g></svg>",
  );

// Status of a single MCP server as returned by the /.pomerium/mcp/routes*
// endpoints.
type MCPServerStatus = {
  url: string;
  connected?: boolean;
  token_expires_at?: string;
  refresh_token_available?: boolean;
};

type MCPRoutesResponse = {
  servers?: MCPServerStatus[];
  errors?: Record<string, string>;
};

// formatDuration renders a duration in seconds as a compact human string,
// e.g. "42m" or "3h". Intl.RelativeTimeFormat is not available at the
// TypeScript target used here, so this is done locally.
const formatDuration = (seconds: number): string => {
  const units: [string, number][] = [
    ["d", 86400],
    ["h", 3600],
    ["m", 60],
  ];
  for (const [suffix, unitSeconds] of units) {
    if (seconds >= unitSeconds) {
      return `${Math.floor(seconds / unitSeconds)}${suffix}`;
    }
  }
  return `${Math.floor(seconds)}s`;
};

// describeExpiry renders an expiry timestamp as "expires in …", "expired … ago"
// or "no expiry" when the timestamp is absent or unparseable.
const describeExpiry = (timestamp?: string): string => {
  if (!timestamp) {
    return "no expiry";
  }
  const parsed = Date.parse(timestamp);
  if (Number.isNaN(parsed)) {
    return "no expiry";
  }
  const deltaSeconds = (parsed - Date.now()) / 1000;
  return deltaSeconds >= 0
    ? `expires in ${formatDuration(deltaSeconds)}`
    : `expired ${formatDuration(-deltaSeconds)} ago`;
};

// isExpired reports whether an expiry timestamp is in the past. Absent or
// unparseable timestamps are treated as "not expired".
const isExpired = (timestamp?: string): boolean => {
  if (!timestamp) {
    return false;
  }
  const parsed = Date.parse(timestamp);
  return !Number.isNaN(parsed) && parsed < Date.now();
};

// stateFromRoute maps the portal's `mcp_`-prefixed route fields onto the shape the
// /.pomerium/mcp/routes* endpoints return, so the card has a single state shape.
const stateFromRoute = (route: Route): MCPServerStatus => ({
  url: route.from,
  connected: route.mcp_connected,
  token_expires_at: route.mcp_token_expires_at,
  refresh_token_available: route.mcp_refresh_token_available,
});

type MCPRouteCardProps = {
  route: Route;
};
const MCPRouteCard: FC<MCPRouteCardProps> = ({ route }) => {
  const [tokenState, setTokenState] = useState<MCPServerStatus>(() =>
    stateFromRoute(route),
  );
  const [pending, setPending] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // post calls one of the MCP routes endpoints for this route and applies the
  // returned status to the card.
  const post = async (endpoint: string, action: string) => {
    setPending(true);
    try {
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ routes: [route.from] }),
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        setErrorMessage(
          `Failed to ${action} (${resp.status}): ${text || "unknown error"}`,
        );
        return;
      }
      const body = (await resp.json()) as MCPRoutesResponse;
      const server = body.servers?.find((s) => s.url === route.from);
      if (server) {
        setTokenState(server);
      }
      const routeError = body.errors?.[route.from];
      setErrorMessage(routeError ? `Failed to ${action}: ${routeError}` : null);
    } catch (err) {
      setErrorMessage(
        `Failed to ${action}: ${
          err instanceof Error ? err.message : "network error"
        }`,
      );
    } finally {
      setPending(false);
    }
  };

  const handleDisconnect = () =>
    post("/.pomerium/mcp/routes/disconnect", "disconnect");
  const handleRefresh = () => post("/.pomerium/mcp/routes/refresh", "refresh");

  // One source of truth for the three presentation states, so the chip's icon,
  // label and color don't each re-derive it.
  const status = !tokenState.connected
    ? { label: "Not Connected", color: "default" as const, live: false }
    : isExpired(tokenState.token_expires_at)
      ? { label: "Expired", color: "warning" as const, live: false }
      : { label: "Connected", color: "success" as const, live: true };

  const refreshTokenLabel = tokenState.refresh_token_available
    ? "available"
    : "not available";

  return (
    <Card
      raised={true}
      sx={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
      }}
    >
      <CardHeader
        avatar={
          route.logo_url ? (
            <Avatar
              src={route.logo_url}
              variant="square"
              slotProps={{
                img: {
                  sx: {
                    objectFit: "scale-down",
                  },
                },
              }}
            />
          ) : (
            <Avatar src={mcpLogoDataURI} />
          )
        }
        title={
          <Box
            component="span"
            sx={{
              wordBreak: "break-all",
            }}
          >
            {route.name}
          </Box>
        }
        subheader={
          <Chip
            icon={status.live ? <Wifi size={14} /> : <WifiOff size={14} />}
            label={status.label}
            size="small"
            color={status.color}
            variant="outlined"
            sx={{ mt: 0.5 }}
          />
        }
      />
      {(route.description || tokenState.connected) && (
        <CardContent sx={{ pt: 0 }}>
          {route.description && (
            <Typography variant="body2">{route.description}</Typography>
          )}
          {tokenState.connected && (
            <>
              <Typography
                variant="caption"
                component="div"
                color="textSecondary"
              >
                Access token: {describeExpiry(tokenState.token_expires_at)}
              </Typography>
              <Typography
                variant="caption"
                component="div"
                color="textSecondary"
              >
                Refresh token: {refreshTokenLabel}
              </Typography>
            </>
          )}
        </CardContent>
      )}
      {errorMessage && (
        <Alert
          severity="error"
          onClose={() => setErrorMessage(null)}
          sx={{ mx: 1 }}
        >
          {errorMessage}
        </Alert>
      )}
      <CardActions sx={{ justifyContent: "flex-end", pt: 0 }}>
        {tokenState.connected ? (
          <>
            <Button
              size="small"
              color="primary"
              disabled={pending}
              onClick={handleRefresh}
            >
              Refresh
            </Button>
            <Button
              size="small"
              color="error"
              disabled={pending}
              onClick={handleDisconnect}
            >
              Disconnect
            </Button>
          </>
        ) : route.mcp_connect_url ? (
          <Button
            size="small"
            color="primary"
            href={route.mcp_connect_url}
            component="a"
          >
            Connect
          </Button>
        ) : null}
      </CardActions>
    </Card>
  );
};
export default MCPRouteCard;
