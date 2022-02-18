import { Session } from "../types";
import IDField from "./IDField";
import Section from "./Section";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableRow from "@mui/material/TableRow";
import React, { FC } from "react";
import ClaimValue from "./ClaimValue";
import {startCase} from "lodash";

export type SessionDetailsProps = {
  session: Session;
};
export const SessionDetails: FC<SessionDetailsProps> = ({ session }) => {
  return (
    <Section title="User Details">
      <Stack spacing={3}>
        <TableContainer>
          <Table size="small">
            <TableBody>
              <TableRow>
                <TableCell width={'18%'} variant="head">Session ID</TableCell>
                <TableCell align="left">
                  <IDField value={session?.id} />
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell variant="head">User ID</TableCell>
                <TableCell align="left">
                  <IDField value={session?.userId} />
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell variant="head">Expires At</TableCell>
                <TableCell align="left">{session?.expiresAt || ""}</TableCell>
              </TableRow>
              {Object.entries(session?.claims || {}).map(
                ([key, values]) => (
                <TableRow key={key}>
                  <TableCell variant="head">{startCase(key)}</TableCell>
                  <TableCell align="left">
                    {values?.map((v, i) => (
                      <React.Fragment key={`${v}`}>
                        {i > 0 ? <br /> : <></>}
                        <ClaimValue claimKey={key} claimValue={v} />
                      </React.Fragment>
                    ))}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Stack>
    </Section>
  );
};
export default SessionDetails;
