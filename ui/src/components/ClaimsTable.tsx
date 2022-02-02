import { Claims } from "../types";
import ClaimValue from "./ClaimValue";
import Alert from "@mui/material/Alert";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import React, { FC } from "react";

type ClaimsTableProps = {
  claims: Claims;
};
const ClaimsTable: FC<ClaimsTableProps> = ({ claims }) => {
  const entries = Object.entries(claims || {});
  entries.sort(([a], [b]) => a.localeCompare(b));

  return (
    <TableContainer>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell variant="head">Claims</TableCell>
            <TableCell variant="head"></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {entries.length > 0 ? (
            entries.map(([key, values]) => (
              <TableRow key={key}>
                <TableCell>{key}</TableCell>
                <TableCell>
                  {values?.map((v, i) => (
                    <React.Fragment key={`${v}`}>
                      {i > 0 ? <br /> : <></>}
                      <ClaimValue claimKey={key} claimValue={v} />
                    </React.Fragment>
                  ))}
                </TableCell>
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
