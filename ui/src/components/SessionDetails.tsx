import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableRow from "@mui/material/TableRow";
import React, { FC } from "react";

import { Profile, Session } from "../types";
import ClaimRow from "./ClaimRow";
import IDField from "./IDField";
import Section from "./Section";

export type SessionDetailsProps = {
  session: Session;
  profile: Profile;
};
export const SessionDetails: FC<SessionDetailsProps> = ({
  session,
  profile,
}) => {
  return (
    <Section title="User Details">
      <Stack spacing={3}>
        <TableContainer>
          <Table size="small">
            <TableBody>
              <TableRow>
                <TableCell width={"18%"} variant="head">
                  Session ID
                </TableCell>
                <TableCell align="left">
                  <IDField value={session?.id} />
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell variant="head">User ID</TableCell>
                <TableCell align="left">
                  <IDField
                    value={session?.userId || `${profile?.claims?.sub}`}
                  />
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell variant="head">Expires At</TableCell>
                <TableCell align="left">{session?.expiresAt || ""}</TableCell>
              </TableRow>
              {Object.entries(session?.claims || {}).map(([key, values]) => (
                <ClaimRow
                  key={`session/${key}`}
                  claimKey={key}
                  claimValue={values}
                />
              ))}
              {Object.entries(profile?.claims || {}).map(([key, value]) => (
                <ClaimRow
                  key={`profile/${key}`}
                  claimKey={key}
                  claimValue={value}
                />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Stack>
    </Section>
  );
};
export default SessionDetails;
