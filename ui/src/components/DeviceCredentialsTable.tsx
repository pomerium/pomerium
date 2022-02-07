import IDField from "./IDField";
import Alert from "@mui/material/Alert";
import Button from "@mui/material/Button";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import React, { FC } from "react";

export type DeviceCredentialsTableProps = {
  csrfToken: string;
  ids: string[];
  webAuthnUrl: string;
};
export const DeviceCredentialsTable: FC<DeviceCredentialsTableProps> = ({
  csrfToken,
  ids,
  webAuthnUrl
}) => {
  return (
    <TableContainer>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {ids?.length > 0 ? (
            ids?.map((id) => (
              <TableRow key={id}>
                <TableCell>
                  <IDField value={id} />
                </TableCell>
                <TableCell>
                  <form action={webAuthnUrl} method="POST">
                    <input
                      type="hidden"
                      name="_pomerium_csrf"
                      value={csrfToken}
                    />
                    <input type="hidden" name="action" value="unregister" />
                    <input
                      type="hidden"
                      name="pomerium_device_credential_id"
                      value={id}
                    />
                    <Button size="small" type="submit" variant="contained">
                      Delete
                    </Button>
                  </form>
                </TableCell>
              </TableRow>
            ))
          ) : (
            <TableRow>
              <TableCell colSpan={2} padding="none">
                <Alert severity="warning" square>
                  No device credentials found.
                </Alert>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );
};
export default DeviceCredentialsTable;
