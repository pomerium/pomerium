import {
  Alert,
  Box,
  Button,
  Container,
  Grid,
  Link,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableRow,
  Typography,
} from "@mui/material";
import type { FC } from "react";
import React, { useState } from "react";

import type { AgenticApprovePageData } from "../types";
import MCPRouteCard from "./MCPRouteCard";
import Section from "./Section";

type KeyValueTableProps = {
  rows: { key: string; value: string }[];
  keyWidth: string;
};
// KeyValueTable renders the run's disclosures — labels and executor claims —
// which are both plain key/value pairs shown verbatim.
const KeyValueTable: FC<KeyValueTableProps> = ({ rows, keyWidth }) => (
  <Table size="small">
    <TableBody>
      {rows.map((row) => (
        <TableRow key={row.key}>
          <TableCell sx={{ width: keyWidth }}>{row.key}</TableCell>
          <TableCell sx={{ wordBreak: "break-all" }}>{row.value}</TableCell>
        </TableRow>
      ))}
    </TableBody>
  </Table>
);

type AgenticApprovePageProps = {
  data: AgenticApprovePageData;
};
const AgenticApprovePage: FC<AgenticApprovePageProps> = ({ data }) => {
  const [connectError, setConnectError] = useState<string | null>(
    data.connectError || null,
  );
  const labels = data.labels || [];
  const executor = data.executor || [];
  const mcpServers = data.mcpServers || [];

  return (
    <Container maxWidth="md">
      <Stack spacing={2}>
        {connectError && (
          <Alert severity="warning" onClose={() => setConnectError(null)}>
            Connection failed: {connectError}
          </Alert>
        )}
        <Section
          title="Approve Agentic Run"
          footer={`Signed in as ${data.userEmail || data.userId}`}
        >
          <Stack spacing={2}>
            <Typography>
              An agent is requesting to act on your behalf:
            </Typography>
            <Paper
              variant="outlined"
              sx={{
                padding: 2,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {data.prompt}
            </Paper>
            {labels.length > 0 && (
              <KeyValueTable rows={labels} keyWidth="30%" />
            )}
          </Stack>
        </Section>

        {mcpServers.length > 0 && (
          <Section
            title="MCP Servers"
            footer={
              data.needsConnect
                ? "Some of these need you to connect an upstream account first. Until you do, the agent won't be able to use them on your behalf."
                : undefined
            }
          >
            <Stack spacing={2}>
              <Typography>
                You are allowing the agent to access these MCP servers on your
                behalf:
              </Typography>
              <Grid container spacing={2}>
                {mcpServers.map((route) => (
                  <Grid key={route.id} sx={{ width: 300 }}>
                    {/* The approver connects here; disconnecting is the routes
                        portal's job, so this card only offers Connect. */}
                    <MCPRouteCard route={route} allowDisconnect={false} />
                  </Grid>
                ))}
              </Grid>
            </Stack>
          </Section>
        )}

        {executor.length > 0 && (
          <Section title="Executor">
            <Stack spacing={2}>
              <Typography>
                Only this specific agent instance may act — no other workload
                can use this approval:
              </Typography>
              <KeyValueTable
                rows={executor.map((claim) => ({
                  key: claim.path,
                  value: claim.value,
                }))}
                keyWidth="40%"
              />
            </Stack>
          </Section>
        )}

        <Section title="Approve">
          <Stack spacing={2}>
            <Typography>
              This run stays active for as long as you remain signed in. The
              agent keeps renewing its access on your behalf while your session
              is alive, and it stops automatically once you sign out or your
              session ends.
            </Typography>
            <Alert severity="info">
              After you approve, you will be taken to your{" "}
              {data.sessionsUrl ? (
                <Link href={data.sessionsUrl}>session list</Link>
              ) : (
                "session list"
              )}
              , where you can revoke this session at any time — which stops the
              run.
            </Alert>
            <Box component="form" method="POST" action={data.approvePath}>
              <input type="hidden" name="code" value={data.code} />
              <Button
                type="submit"
                variant="contained"
                disabled={data.needsConnect}
              >
                Approve
              </Button>
            </Box>
          </Stack>
        </Section>
      </Stack>
    </Container>
  );
};
export default AgenticApprovePage;
