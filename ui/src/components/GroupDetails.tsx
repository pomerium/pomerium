import { Group } from "../types";
import IDField from "./IDField";
import Section from "./Section";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import React, { FC } from "react";

export type GroupDetailsProps = {
  groups: Group[];
};
export const GroupDetails: FC<GroupDetailsProps> = ({ groups }) => {
  return (
    <Section title="Groups">
      <TableContainer>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Name</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {groups?.map((group) => (
              <TableRow key={group?.id}>
                <TableCell>
                  <IDField value={group?.id} />
                </TableCell>
                <TableCell>{group?.name}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Section>
  );
};
export default GroupDetails;
