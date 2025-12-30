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
} from "@mui/material";
import type { FC } from "react";
import { ExternalLink } from "react-feather";
import { SmallTooltip } from "src/components/Tooltips";
import type { SessionBindingInfoPageData } from "src/types";

import Section from "./Section";
import SidebarPage from "./SidebarPage";

type SessionBindingInfoProps = {
  data: SessionBindingInfoPageData;
};

const SessionBindingInfoPage: FC<SessionBindingInfoProps> = ({ data }) => {
  return (
    <SidebarPage data={data}>
      <Section
        title="SSH Sessions"
        icon={
          <IconButton
            component="a"
            href="https://www.pomerium.com/docs/capabilities/native-ssh-access"
            target="_blank"
            rel="noopener noreferrer"
            size="small"
            aria-label="SSH documentation"
          >
            <ExternalLink size={18} />
          </IconButton>
        }
      >
        <SessionBindingInfoContent data={data}></SessionBindingInfoContent>
      </Section>
    </SidebarPage>
  );
};

const SessionBindingInfoContent: FC<SessionBindingInfoProps> = ({ data }) => {
  return (
    <>
      <TableContainer component={Paper} sx={{ maxWidth: 1200, mb: 2 }}>
        <Table size="small" aria-label="metadata table">
          <TableHead>
            <TableRow>
              <TableCell variant="head">Protocol</TableCell>
              <TableCell variant="head" sx={{ whiteSpace: "nowrap" }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  Fingerprint
                  <SmallTooltip description="Run `ssh-keygen -l -f <client-pub-key>` to compare fingerprints." />
                </Box>
              </TableCell>
              <TableCell variant="head">Source IP</TableCell>
              <TableCell variant="head" align="right">
                Issued
              </TableCell>
              <TableCell variant="head" align="right">
                Expires
              </TableCell>
              <TableCell variant="head" align="right">
                Actions
              </TableCell>
              <TableCell variant="head" align="center">
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  Remembered
                  <SmallTooltip description="Trust this device for future SSH logins (skip re-authentication until revoked)." />
                </Box>
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.sessionBindings
              ?.filter((s) => s.Protocol === "ssh")
              .map((s) => (
                <TableRow key={s.DetailsSSH.FingerprintID}>
                  <TableCell>{s.Protocol}</TableCell>
                  <TableCell component="th" scope="row">
                    <Box
                      sx={{
                        display: "flex",
                        alignItems: "center",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {s.DetailsSSH.FingerprintID}
                      <IconButton
                        aria-label="Copy fingerprint"
                        size="small"
                        onClick={() => {
                          navigator.clipboard.writeText(
                            s.DetailsSSH.FingerprintID
                          );
                        }}
                      >
                        <ContentCopyIcon fontSize="small"></ContentCopyIcon>
                      </IconButton>
                    </Box>
                  </TableCell>
                  <TableCell>{s.DetailsSSH.SourceAddress}</TableCell>
                  <TableCell align="right">{s.IssuedAt}</TableCell>
                  <TableCell align="right">{s.ExpiresAt}</TableCell>
                  <TableCell align="right">
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
                      <Button size="small" type="submit" variant="contained">
                        Revoke
                      </Button>
                    </Box>
                  </TableCell>
                  <TableCell align="center">
                    <Box
                      component="form"
                      action={s.RevokeIdentityBindingURL}
                      method="POST"
                      sx={{
                        display: "inline-flex",
                        gap: 1,
                        alignItems: "center",
                      }}
                    >
                      <input
                        type="hidden"
                        name="sessionBindingID"
                        value={s.SessionBindingID}
                      />
                      <Button
                        size="small"
                        type="submit"
                        variant="contained"
                        disabled={!s.HasIdentityBinding}
                      >
                        Revoke
                      </Button>
                    </Box>
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
