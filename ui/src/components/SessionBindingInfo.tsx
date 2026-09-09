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
  Typography,
} from "@mui/material";
import type { FC } from "react";

import type { SessionBindingInfoPageData } from "../types";
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
              <TableRow
                key={`${s.Protocol}:${s.Resource}:${s.SessionBindingID}`}
              >
                <TableCell>{s.Protocol}</TableCell>
                <TableCell component="th" scope="row">
                  <Typography variant="body2">{s.Resource}</Typography>
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
                      <input
                        type="hidden"
                        name="protocol"
                        value={s.Protocol}
                      />
                      <Button size="small" type="submit" variant="contained">
                        Revoke
                      </Button>
                    </Box>
                  ) : (
                    "—"
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
};

export default SessionBindingInfoPage;
