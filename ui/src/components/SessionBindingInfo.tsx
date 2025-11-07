import { FC } from "react";
import { SessionBindingInfoPageData } from "src/types";
import {
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  FormControlLabel,
  Box,
  Checkbox,
  Typography,
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
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {data.sessions?.map((s) => (
                            <TableRow key={s.SessionID}>
                            <TableCell component="th" scope="row">{s.SessionID}</TableCell>
                            <TableCell>{s.Protocol}</TableCell>
                            <TableCell>{s.IssuedAt}</TableCell>
                            <TableCell>{s.ExpiresAt}</TableCell>
                            <TableCell>
                              <Box
                                component="form"
                                action={s.RevokeURL}
                                method="POST"
                                sx={{ display: "inline-flex", gap: 1 }}
                              >
                                <input type="hidden" name="sessionID" value={s.SessionID} />
                                <Button size="small" type="submit" variant="contained">
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
