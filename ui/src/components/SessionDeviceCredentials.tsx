import DeviceCredentialsTable from "../components/DeviceCredentialsTable";
import { Footer } from "../components/Section";
import { Session, User } from "../types";
import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import React, { FC } from "react";

export type SessionDeviceCredentialsProps = {
  csrfToken: string;
  user: User;
  session: Session;
  webAuthnUrl: string;
};
export const SessionDeviceCredentials: FC<SessionDeviceCredentialsProps> = ({
  csrfToken,
  user,
  session,
  webAuthnUrl
}) => {
  const currentSessionDeviceCredentialIds = [];
  const otherDeviceCredentialIds = [];
  user?.deviceCredentialIds?.forEach((id) => {
    if (session?.deviceCredentials?.find((cred) => cred?.id === id)) {
      currentSessionDeviceCredentialIds.push(id);
    } else {
      otherDeviceCredentialIds.push(id);
    }
  });

  return (
    <Paper sx={{ overflow: "hidden" }}>
      <Stack>
        <Toolbar>
          <Typography variant="h4" flexGrow={1}>
            Current Session Device Credentials
          </Typography>
        </Toolbar>
        <Box sx={{ padding: 3, paddingTop: 0 }}>
          <DeviceCredentialsTable
            csrfToken={csrfToken}
            ids={currentSessionDeviceCredentialIds}
            webAuthnUrl={webAuthnUrl}
          />
        </Box>
        {otherDeviceCredentialIds?.length > 0 ? (
          <>
            <Toolbar>
              <Typography variant="h4" flexGrow={1}>
                Other Device Credentials
              </Typography>
            </Toolbar>
            <Box sx={{ padding: 3, paddingTop: 0 }}>
              <DeviceCredentialsTable
                csrfToken={csrfToken}
                ids={otherDeviceCredentialIds}
                webAuthnUrl={webAuthnUrl}
              />
            </Box>
          </>
        ) : (
          <></>
        )}
        <Footer>
          <Typography variant="caption">
            Register device with <a href={webAuthnUrl}>WebAuthn</a>.
          </Typography>
        </Footer>
      </Stack>
    </Paper>
  );
};
export default SessionDeviceCredentials;
