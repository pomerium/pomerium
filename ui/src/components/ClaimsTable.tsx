import Alert from "@mui/material/Alert";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import React, { FC } from "react";

type ClaimsTableProps = {
  claims: Record<string, unknown>;
};
const ClaimsTable: FC<ClaimsTableProps> = ({ claims }) => {
  const entries = Object.entries(claims);
  entries.sort(([a], [b]) => a.localeCompare(b));

  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Claims</TableCell>
            <TableCell></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {entries.length > 0 ? (
            entries.map(([key, value]) => (
              <TableRow key={key}>
                <TableCell>{key}</TableCell>
                <TableCell>{`${value}`}</TableCell>
              </TableRow>
            ))
          ) : (
            <TableRow>
              <TableCell colSpan={2} padding="none">
                <Alert severity="warning" square={true}>
                  No Claims Found
                </Alert>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );
};
export default ClaimsTable;
