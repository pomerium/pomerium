import type { FC } from "react";
import type { SessionBindingInfoPageData } from "src/types";
import {SmallTooltip} from "src/components/Tooltips";
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
} from "@mui/material";

type SessionBindingInfoProps = {
    data: SessionBindingInfoPageData;
}


const SessionBindingInfoPage : FC<SessionBindingInfoProps> = ({data}) => {
    return (
        <>
            <TableContainer component={Paper} sx={{ maxWidth: 1000, mx: "auto", mb: 2 }}>
                    <Table size="small" aria-label="metadata table">
                      <TableHead>
                        <TableRow>
                          <TableCell variant="head">Session ID</TableCell>
                          <TableCell variant="head">Protocol</TableCell>
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
                        {data.sessionBindings?.map((s) => (
                            <TableRow key={s.SessionBindingID}>
                            <TableCell component="th" scope="row">{s.SessionBindingID}</TableCell>
                            <TableCell>{s.Protocol}</TableCell>
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
