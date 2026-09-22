import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import {
  Box,
  Button,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from "@mui/material";
import type { FC } from "react";
import { useEffect, useRef } from "react";

import type {
  DetailsAgentic,
  SessionBindingData,
  SessionBindingInfoPageData,
} from "../types";
import Section from "./Section";
import SidebarPage from "./SidebarPage";
import { SmallTooltip } from "./Tooltips";

type SessionBindingInfoProps = {
  data: SessionBindingInfoPageData;
};

const SessionBindingInfoPage: FC<SessionBindingInfoProps> = ({ data }) => {
  return (
    <SidebarPage data={data}>
      <Section title="Client bindings">
        <SessionBindingInfoContent data={data}></SessionBindingInfoContent>
      </Section>
    </SidebarPage>
  );
};

const SessionBindingInfoContent: FC<SessionBindingInfoProps> = ({ data }) => {
  // TODO: SSH uses a weird identity binding we won't need when we migrate to idpsession.IDPSession.
  return (
    <>
      <TableContainer component={Paper} sx={{ maxWidth: 1200, mb: 2 }}>
        <Table size="small" aria-label="metadata table">
          <TableHead>
            <TableRow>
              <TableCell variant="head">Protocol</TableCell>
              <TableCell variant="head">Resource</TableCell>
              <TableCell variant="head">Client</TableCell>
              <TableCell variant="head">Initiated at</TableCell>
              <TableCell variant="head">Expires at</TableCell>
              <TableCell variant="head">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.sessionBindings?.map((s) => (
              <SessionBindingRow
                key={`${s.Protocol}:${s.Resource}:${s.SessionBindingID}`}
                binding={s}
                reauthEnabled={data.reauth_enabled}
                highlighted={
                  !!data.highlight && s.SessionBindingID === data.highlight
                }
              />
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
};

// SessionBindingRow is one binding. A row may be highlighted — the agentic
// approval flow sends the approver here pointing at the run they just approved
// — in which case it is marked selected and scrolled into view, since the run
// they came to see may be well down a long list.
const SessionBindingRow: FC<{
  binding: SessionBindingData;
  reauthEnabled: boolean;
  highlighted: boolean;
}> = ({ binding: s, reauthEnabled, highlighted }) => {
  const ref = useRef<HTMLTableRowElement>(null);
  useEffect(() => {
    if (highlighted) {
      ref.current?.scrollIntoView({ block: "center" });
    }
  }, [highlighted]);

  return (
    <TableRow
      ref={ref}
      selected={highlighted}
      sx={
        highlighted
          ? { outline: 2, outlineOffset: -2, outlineColor: "primary.main" }
          : undefined
      }
    >
      <TableCell>{s.Protocol}</TableCell>
      <TableCell component="th" scope="row">
        <Typography variant="body2">
          {s.Resource}
          {s.IsCurrentBrowser && (
            <Box component="span" sx={{ fontWeight: "bold" }}>
              {" "}
              (This browser)
            </Box>
          )}
        </Typography>
        {s.DetailsSSH && (
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              whiteSpace: "nowrap",
            }}
          >
            <Typography variant="caption">
              {s.DetailsSSH.FingerprintID}
            </Typography>
            <SmallTooltip description="Run `ssh-keygen -l -f <client-pub-key>` to check against this fingerprint" />
            <IconButton
              aria-label="Copy fingerprint"
              size="small"
              onClick={() => {
                navigator.clipboard.writeText(
                  s.DetailsSSH?.FingerprintID ?? "",
                );
              }}
            >
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Box>
        )}
        {s.DetailsAgentic && <AgenticDetails details={s.DetailsAgentic} />}
      </TableCell>
      <TableCell>
        <Typography variant="body2">
          {s.ClientAddress || "Not recorded"}
        </Typography>
      </TableCell>
      <TableCell>{s.InitiatedAt || "Not recorded"}</TableCell>
      <TableCell>{s.ExpiresAt}</TableCell>
      <TableCell>
        {s.RevokeSessionBindingURL ? (
          <Box
            component="form"
            action={s.RevokeSessionBindingURL}
            method="POST"
            sx={{ display: "inline-flex", gap: 1 }}
          >
            <input
              type="hidden"
              name="sessionBindingID"
              value={s.SessionBindingID}
            />
            <input type="hidden" name="protocol" value={s.Protocol} />
            <Button
              size="small"
              type="submit"
              variant="contained"
              disabled={s.Protocol === "Browser" && !reauthEnabled}
            >
              Logout
            </Button>
          </Box>
        ) : (
          "—"
        )}
      </TableCell>
    </TableRow>
  );
};

// AgenticDetails is the sub-line block under an agentic run's headline: what the
// user approved, which workload is acting as them, and the run id they can quote.
// The headline itself is the template name, so it is not repeated here.
const AgenticDetails: FC<{ details: DetailsAgentic }> = ({ details }) => {
  const labels = Object.entries(details.Labels ?? {})
    .filter(([k]) => k !== "template")
    .sort(([a], [b]) => a.localeCompare(b));
  const claims = Object.entries(details.WorkloadClaims ?? {}).sort(([a], [b]) =>
    a.localeCompare(b),
  );

  return (
    <Box sx={{ mt: 0.5 }}>
      {details.Prompt && (
        <Tooltip title={details.Prompt}>
          <Typography
            variant="caption"
            component="div"
            sx={{
              fontStyle: "italic",
              maxWidth: 420,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            “{details.Prompt}”
          </Typography>
        </Tooltip>
      )}
      {claims.map(([path, value]) => (
        <Typography key={path} variant="caption" component="div">
          {path}: {value}
        </Typography>
      ))}
      {labels.map(([key, value]) => (
        <Typography key={key} variant="caption" component="div">
          {key}: {value}
        </Typography>
      ))}
      {details.RunID && (
        <Box sx={{ display: "flex", alignItems: "center" }}>
          <Typography variant="caption">{details.RunID}</Typography>
          <SmallTooltip description="The run id. Quote it when reporting a problem with this agent run." />
          <IconButton
            aria-label="Copy run id"
            size="small"
            onClick={() => {
              navigator.clipboard.writeText(details.RunID);
            }}
          >
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Box>
      )}
    </Box>
  );
};

export default SessionBindingInfoPage;
