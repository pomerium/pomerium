import {
  Alert,
  Avatar,
  Box,
  Card,
  CardActionArea,
  CardContent,
  CardHeader,
  Grid,
  IconButton,
  Paper,
  Snackbar,
  Stack,
  Typography,
} from "@mui/material";
import type { FC } from "react";
import React, { useEffect, useState } from "react";
import { Clipboard, Link } from "react-feather";

import type { Route, RoutesPageData } from "../types";
import MCPRouteCard from "./MCPRouteCard";
import Section from "./Section";
import SidebarPage from "./SidebarPage";

type RouteCardProps = {
  route: Route;
};
const RouteCard: FC<RouteCardProps> = ({ route }) => {
  const [showSnackbar, setShowSnackbar] = useState(false);

  const handleClick = (evt: React.MouseEvent) => {
    if (route.connect_command) {
      evt.preventDefault();
      navigator.clipboard.writeText(route.connect_command);
      setShowSnackbar(true);
    }
  };

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
      <CardActionArea
        sx={{ height: "100%" }}
        href={route.from}
        target="_blank"
        onClick={handleClick}
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
            ) : route.type === "tcp" ? (
              <Avatar>TCP</Avatar>
            ) : route.type === "udp" ? (
              <Avatar>UDP</Avatar>
            ) : (
              <Avatar>
                <Link />
              </Avatar>
            )
          }
          action={
            route.connect_command && (
              <IconButton title="Copy Command">
                <Clipboard />
              </IconButton>
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
        />
        <CardContent>
          {route.description && (
            <Typography variant="body2">{route.description}</Typography>
          )}
          {route.connect_command && (
            <Box
              component="span"
              sx={{
                fontFamily: '"DM Mono"',
                fontSize: "12px",
                wordBreak: "break-all",
              }}
            >
              {route.connect_command}
            </Box>
          )}
        </CardContent>
      </CardActionArea>
      <Snackbar
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        open={showSnackbar}
        autoHideDuration={3000}
        onClose={() => setShowSnackbar(false)}
        message="Copied to Clipboard"
      />
    </Card>
  );
};

type RoutesSectionProps = {
  type: "http" | "tcp" | "udp";
  title: string;
  allRoutes: Route[];
};
const RoutesSection: FC<RoutesSectionProps> = ({ type, title, allRoutes }) => {
  const routes = allRoutes?.filter((r) => r.type === type);
  if (routes?.length === 0) {
    return <></>;
  }

  return (
    <Section title={title}>
      <Grid container spacing={2} justifyContent="center">
        {routes?.map((r) => (
          <Grid key={r.id} item sx={{ width: 300 }}>
            <RouteCard route={r} />
          </Grid>
        ))}
      </Grid>
    </Section>
  );
};

type MCPRoutesSectionProps = {
  allRoutes: Route[];
};
const MCPRoutesSection: FC<MCPRoutesSectionProps> = ({ allRoutes }) => {
  const routes = allRoutes?.filter((r) => r.type === "mcp");
  if (routes?.length === 0) {
    return <></>;
  }

  return (
    <Section title="MCP Servers">
      <Grid container spacing={2} justifyContent="center">
        {routes?.map((r) => (
          <Grid key={r.id} item sx={{ width: 300 }}>
            <MCPRouteCard route={r} />
          </Grid>
        ))}
      </Grid>
    </Section>
  );
};

type RoutesPageProps = {
  data: RoutesPageData;
};
const RoutesPage: FC<RoutesPageProps> = ({ data }) => {
  const [connectError, setConnectError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get("connect_error");
    if (error) {
      setConnectError(error);
      // Clean the URL so the error doesn't persist on refresh.
      params.delete("connect_error");
      const clean = params.toString();
      const newURL = window.location.pathname + (clean ? "?" + clean : "");
      window.history.replaceState({}, "", newURL);
    }
  }, []);

  return (
    <SidebarPage data={data}>
      <Stack spacing={2}>
        {connectError && (
          <Alert severity="warning" onClose={() => setConnectError(null)}>
            Connection failed: {connectError}
          </Alert>
        )}
        {data?.mcp_status_error && (
          <Alert severity="warning">{data.mcp_status_error}</Alert>
        )}
        {data?.routes?.length > 0 ? (
          <>
            <RoutesSection
              type={"http"}
              title={"HTTP Routes"}
              allRoutes={data.routes}
            />
            {data?.runtimeFlags?.mcp && (
              <MCPRoutesSection allRoutes={data.routes} />
            )}
            <RoutesSection
              type={"tcp"}
              title={"TCP Routes"}
              allRoutes={data.routes}
            />
            <RoutesSection
              type={"udp"}
              title={"UDP Routes"}
              allRoutes={data.routes}
            />
          </>
        ) : (
          <Paper sx={{ padding: 3 }}>
            <Typography>No accessible routes found</Typography>
          </Paper>
        )}
      </Stack>
    </SidebarPage>
  );
};
export default RoutesPage;
