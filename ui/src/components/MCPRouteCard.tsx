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

type MCPRouteCardProps = {
  route: Route;
  // allowDisconnect offers the Disconnect action for a connected route. The
  // agentic approval page turns it off: an approver is there to connect what
  // the run needs, and disconnecting belongs on the routes portal.
  allowDisconnect?: boolean;
};
const MCPRouteCard: FC<MCPRouteCardProps> = ({
  route,
  allowDisconnect = true,
}) => {
  const [connected, setConnected] = useState(route.mcp_connected ?? false);
  const [pending, setPending] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  // A listed server with no upstream to connect to has no connection state to
  // show, so the chip and the actions are both omitted for it.
  const showConnection = route.mcp_needs_oauth !== false;

  const handleDisconnect = async () => {
    setPending(true);
    try {
      const resp = await fetch("/.pomerium/mcp/routes/disconnect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ routes: [route.from] }),
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        setErrorMessage(
          `Failed to disconnect (${resp.status}): ${text || "unknown error"}`,
        );
        return;
      }
      setConnected(false);
    } catch (err) {
      setErrorMessage(
        `Failed to disconnect: ${
          err instanceof Error ? err.message : "network error"
        }`,
      );
    } finally {
      setPending(false);
    }
  };

  // At most one action is offered: Disconnect for a connection this page is
  // allowed to drop, Connect for one that can be made, and nothing otherwise.
  let action: React.ReactNode = null;
  if (showConnection && connected && allowDisconnect) {
    action = (
      <Button
        size="small"
        color="error"
        disabled={pending}
        onClick={handleDisconnect}
      >
        Disconnect
      </Button>
    );
  } else if (showConnection && !connected && route.mcp_connect_url) {
    action = (
      <Button
        size="small"
        color="primary"
        href={route.mcp_connect_url}
        component="a"
      >
        Connect
      </Button>
    );
  }

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
          showConnection ? (
            <Chip
              icon={connected ? <Wifi size={14} /> : <WifiOff size={14} />}
              label={connected ? "Connected" : "Not Connected"}
              size="small"
              color={connected ? "success" : "default"}
              variant="outlined"
              sx={{ mt: 0.5 }}
            />
          ) : undefined
        }
      />
      {route.description && (
        <CardContent sx={{ pt: 0 }}>
          <Typography variant="body2">{route.description}</Typography>
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
        {action}
      </CardActions>
    </Card>
  );
};
export default MCPRouteCard;
