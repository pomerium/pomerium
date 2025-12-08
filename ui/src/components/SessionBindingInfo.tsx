import type { FC } from "react";
import type { SessionBindingInfoPageData } from "src/types";
import {SmallTooltip} from "src/components/Tooltips";
import SidebarPage from "./SidebarPage";
import Section from "./Section";
import ContentCopyIcon from '@mui/icons-material/ContentCopy';

import {
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Box,
  IconButton,
} from "@mui/material";

type SessionBindingInfoProps = {
    data: SessionBindingInfoPageData;
}

const SessionBindingInfoPage: FC<SessionBindingInfoProps> = ({data}) => {
  return (
     <SidebarPage data={data}>
        <Section title="Client bindings">
          <SessionBindingInfoContent data={data}></SessionBindingInfoContent>
        </Section>
     </SidebarPage>
  )
}

const SessionBindingInfoContent : FC<SessionBindingInfoProps> = ({data}) => {
    return (
        <>
            <TableContainer component={Paper} sx={{ maxWidth: 1200,  mb: 2 }}>
                    <Table size="small" aria-label="metadata table">
                      <TableHead>
                        <TableRow>
                          <TableCell variant="head">Protocol</TableCell>
                          <TableCell variant="head" sx={{ whiteSpace: 'nowrap'}}>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                              Fingerprint
                              <SmallTooltip description="Run `ssh-keygen -l -f <client-pub-key>` to check against your fingerprint"/>
                            </Box>
                          </TableCell>
                          <TableCell variant="head">Initiated From</TableCell>
                          <TableCell variant="head">IssuedAt</TableCell>
                          <TableCell variant="head">ExpiresAt</TableCell>
                          <TableCell variant="head">Actions</TableCell>
                           <TableCell variant="head">
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                              Remember me?
                              <SmallTooltip description="When enabled, your client is persistently bound to your user. Revoking removes this persistent binding."/>
                            </Box>
                          </TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {data.sessionBindings?.filter((s) => s.Protocol === "ssh").map((s) => (
                            <TableRow key={s.DetailsSSH.FingerprintID}>
                            <TableCell>{s.Protocol}</TableCell>
                            <TableCell component="th" scope="row">
                              <Box sx={{ display: 'flex', alignItems: 'center', whiteSpace: 'nowrap' }}>
                                {s.DetailsSSH.FingerprintID}
                                <IconButton
                                  aria-label="Copy fingerprint"
                                  size="small"
                                  onClick={() => {
                                    navigator.clipboard.writeText(s.DetailsSSH.FingerprintID);
                                  }}
                                >
                                    <ContentCopyIcon fontSize="small"></ContentCopyIcon>
                                </IconButton>
                              </Box>
                            </TableCell>
                            <TableCell>{s.DetailsSSH.SourceAddress}</TableCell>
                            <TableCell>{s.IssuedAt}</TableCell>
                            <TableCell>{s.ExpiresAt}</TableCell>
                            <TableCell>
                              <Box
                                component="form"
                                action={s.RevokeSessionBindingURL}
                                method="POST"
                                sx={{ display: "inline-flex", gap: 1 }}
                              >
                                <input type="hidden" name="sessionBindingID" value={s.SessionBindingID} />
                                <Button size="small" type="submit" variant="contained">
                                  Revoke
                                </Button>
                              </Box>
                            </TableCell>
                            <TableCell>
                              <Box
                                component="form"
                                action={s.RevokeIdentityBindingURL}
                                method="POST"
                                sx={{ display: "inline-flex", gap: 1, alignItems:"center" }}
                              >
                                <input type="hidden" name="sessionBindingID" value={s.SessionBindingID} />
                                <Button size="small" type="submit" variant="contained" disabled={!s.HasIdentityBinding}>
                                  Revoke
                                </Button>
                              </Box>
                            </TableCell>
                          </TableRow>
                        )) }
                      </TableBody>
                    </Table>
                  </TableContainer>
        </>
    )

};

export default SessionBindingInfoPage;
