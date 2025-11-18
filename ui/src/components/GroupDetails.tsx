import {
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from "@mui/material";
import type { FC } from "react";
import React from "react";

import type { Group } from "../types";
import IDField from "./IDField";
import Section from "./Section";

export type GroupDetailsProps = {
  isEnterprise: boolean;
  groups: Group[];
};
export const GroupDetails: FC<GroupDetailsProps> = ({
  isEnterprise,
  groups,
}) => {
  return (
    <Section title="Groups">
      {isEnterprise ? (
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
      ) : (
        <Alert severity="info">
          Groups via directory sync are available in{" "}
          <a href="https://www.pomerium.com/enterprise-sales/">
            Pomerium Enterprise
          </a>
          .
        </Alert>
      )}
    </Section>
  );
};
export default GroupDetails;
