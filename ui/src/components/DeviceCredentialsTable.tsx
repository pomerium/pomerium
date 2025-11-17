import {
  Alert,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from "@mui/material";
import type { FC } from "react";
import React from "react";

import IDField from "./IDField";

export type DeviceCredentialsTableProps = {
  ids: string[];
  webAuthnUrl: string;
};
export const DeviceCredentialsTable: FC<DeviceCredentialsTableProps> = ({
  ids,
  webAuthnUrl,
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
