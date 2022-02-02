import { Session } from "../types";
import ClaimsTable from "./ClaimsTable";
import Section from "./Section";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableRow from "@mui/material/TableRow";
import React, { FC } from "react";

export type SessionDetailsProps = {
  session: Session;
};
export const SessionDetails: FC<SessionDetailsProps> = ({ session }) => {
  return (
    <Section title="Session Details">
      <Stack spacing={3}>
        <TableContainer>
          <Table>
            <TableBody>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>{session?.id || ""}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>User ID</TableCell>
                <TableCell>{session?.userId || ""}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Expires At</TableCell>
                <TableCell>{session?.expiresAt || ""}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </TableContainer>
        <ClaimsTable claims={session?.claims} />
      </Stack>
    </Section>
  );
};
export default SessionDetails;
