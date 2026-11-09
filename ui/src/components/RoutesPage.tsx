import Alert from "@mui/material/Alert";
import Avatar from "@mui/material/Avatar";
import Box from "@mui/material/Box";
import Card from "@mui/material/Card";
import CardActionArea from "@mui/material/CardActionArea";
import CardContent from "@mui/material/CardContent";
import CardHeader from "@mui/material/CardHeader";
import Grid from "@mui/material/Grid";
import IconButton from "@mui/material/IconButton";
import Paper from "@mui/material/Paper";
import Snackbar from "@mui/material/Snackbar";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import type { MouseEvent } from "react";
import { useEffect, useState } from "react";
import Clipboard from "react-feather/dist/icons/clipboard";
import Link from "react-feather/dist/icons/link";

import type { Route, RoutesPageData } from "../types";
import MCPRouteCard from "./MCPRouteCard";
import Section from "./Section";
import SidebarPage from "./SidebarPage";

type RouteCardProps = {
  route: Route;
};
function RouteCard({ route }: RouteCardProps) {
  const [showSnackbar, setShowSnackbar] = useState(false);

  const handleClick = (evt: MouseEvent) => {
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
          {route.description && <Typography variant="body2">{route.description}</Typography>}
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
}

type RoutesSectionProps = {
  type: "http" | "tcp" | "udp";
  title: string;
  allRoutes: Route[];
};
function RoutesSection({ type, title, allRoutes }: RoutesSectionProps) {
  const routes = allRoutes?.filter((r) => r.type === type);
  if (routes?.length === 0) {
    return <></>;
  }

  return (
    <Section title={title}>
      <Grid container spacing={2} sx={{ justifyContent: "center" }}>
        {routes?.map((r) => (
          <Grid key={r.id} sx={{ width: 300 }}>
            <RouteCard route={r} />
          </Grid>
        ))}
      </Grid>
    </Section>
  );
}

type MCPRoutesSectionProps = {
  allRoutes: Route[];
};
function MCPRoutesSection({ allRoutes }: MCPRoutesSectionProps) {
  const routes = allRoutes?.filter((r) => r.type === "mcp");
  if (routes?.length === 0) {
    return <></>;
  }

  return (
    <Section title="MCP Servers">
      <Grid container spacing={2} sx={{ justifyContent: "center" }}>
        {routes?.map((r) => (
          <Grid key={r.id} sx={{ width: 300 }}>
            <MCPRouteCard route={r} />
          </Grid>
        ))}
      </Grid>
    </Section>
  );
}

type RoutesPageProps = {
  data: RoutesPageData;
};
export default function RoutesPage({ data }: RoutesPageProps) {
  const [connectError, setConnectError] = useState<string | null>(() =>
    new URLSearchParams(window.location.search).get("connect_error"),
  );

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("connect_error")) {
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
        {data?.mcp_status_error && <Alert severity="warning">{data.mcp_status_error}</Alert>}
        {data?.routes?.length > 0 ? (
          <>
            <RoutesSection type={"http"} title={"HTTP Routes"} allRoutes={data.routes} />
            {data?.runtimeFlags?.mcp && <MCPRoutesSection allRoutes={data.routes} />}
            <RoutesSection type={"tcp"} title={"TCP Routes"} allRoutes={data.routes} />
            <RoutesSection type={"udp"} title={"UDP Routes"} allRoutes={data.routes} />
          </>
        ) : (
          <Paper sx={{ padding: 3 }}>
            <Typography>No accessible routes found</Typography>
          </Paper>
        )}
      </Stack>
    </SidebarPage>
  );
}
