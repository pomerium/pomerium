import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import React, { FC } from "react";

import DeviceCredentialsTable from "../components/DeviceCredentialsTable";
import {
  Session,
  User,
  WebAuthnCreationOptions,
  WebAuthnRequestOptions,
} from "../types";
import WebAuthnAuthenticateButton from "./WebAuthnAuthenticateButton";
import WebAuthnRegisterButton from "./WebAuthnRegisterButton";

export type SessionDeviceCredentialsProps = {
  csrfToken: string;
  user: User;
  session: Session;
  webAuthnCreationOptions: WebAuthnCreationOptions;
  webAuthnRequestOptions: WebAuthnRequestOptions;
  webAuthnUrl: string;
};
export const SessionDeviceCredentials: FC<SessionDeviceCredentialsProps> = ({
  csrfToken,
  user,
  session,
  webAuthnCreationOptions,
  webAuthnRequestOptions,
  webAuthnUrl,
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
    <>
      <Paper sx={{ overflow: "hidden" }}>
        <Stack>
          <Toolbar>
            <Typography variant="h4" flexGrow={1}>
              Current Session Device Credentials
            </Typography>

            <Stack direction="row" justifyContent="center" spacing={1}>
              <WebAuthnRegisterButton
                creationOptions={webAuthnCreationOptions}
                csrfToken={csrfToken}
                url={webAuthnUrl}
                size="small"
              />
              <WebAuthnAuthenticateButton
                requestOptions={webAuthnRequestOptions}
                csrfToken={csrfToken}
                url={webAuthnUrl}
                size="small"
              />
            </Stack>
          </Toolbar>
          <Box sx={{ padding: 3, paddingTop: 0 }}>
            <DeviceCredentialsTable
              csrfToken={csrfToken}
              ids={currentSessionDeviceCredentialIds}
              webAuthnUrl={webAuthnUrl}
            />
          </Box>
        </Stack>
      </Paper>

      {otherDeviceCredentialIds?.length > 0 ? (
        <>
          <Paper sx={{ overflow: "hidden" }}>
            <Stack>
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
            </Stack>
          </Paper>
        </>
      ) : (
        <></>
      )}
    </>
  );
};
export default SessionDeviceCredentials;
