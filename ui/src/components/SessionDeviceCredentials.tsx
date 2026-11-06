import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";

import DeviceCredentialsTable from "../components/DeviceCredentialsTable";
import type { Session, User, WebAuthnCreationOptions, WebAuthnRequestOptions } from "../types";
import WebAuthnAuthenticateButton from "./WebAuthnAuthenticateButton";
import WebAuthnRegisterButton from "./WebAuthnRegisterButton";

export type SessionDeviceCredentialsProps = {
  user: User;
  session: Session;
  webAuthnCreationOptions: WebAuthnCreationOptions;
  webAuthnRequestOptions: WebAuthnRequestOptions;
  webAuthnUrl: string;
};
export default function SessionDeviceCredentials({
  user,
  session,
  webAuthnCreationOptions,
  webAuthnRequestOptions,
  webAuthnUrl,
}: SessionDeviceCredentialsProps) {
  const currentSessionDeviceCredentialIds: string[] = [];
  const otherDeviceCredentialIds: string[] = [];
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
            <Typography variant="h4" sx={{ flexGrow: 1 }}>
              Current Session Device Credentials
            </Typography>

            <Stack direction="row" spacing={1} sx={{ justifyContent: "center" }}>
              <WebAuthnRegisterButton
                creationOptions={webAuthnCreationOptions}
                url={webAuthnUrl}
                size="small"
              />
              <WebAuthnAuthenticateButton
                requestOptions={webAuthnRequestOptions}
                url={webAuthnUrl}
                size="small"
              />
            </Stack>
          </Toolbar>
          <Box sx={{ padding: 3, paddingTop: 0 }}>
            <DeviceCredentialsTable
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
                <Typography variant="h4" sx={{ flexGrow: 1 }}>
                  Other Device Credentials
                </Typography>
              </Toolbar>
              <Box sx={{ padding: 3, paddingTop: 0 }}>
                <DeviceCredentialsTable ids={otherDeviceCredentialIds} webAuthnUrl={webAuthnUrl} />
              </Box>
            </Stack>
          </Paper>
        </>
      ) : (
        <></>
      )}
    </>
  );
}
