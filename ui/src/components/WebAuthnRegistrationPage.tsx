import { Stack } from "@mui/material";
import React, { FC } from "react";

import { WebAuthnRegistrationPageData } from "../types";
import ExperimentalIcon from "./ExperimentalIcon";
import Section from "./Section";
import WebAuthnAuthenticateButton from "./WebAuthnAuthenticateButton";
import WebAuthnRegisterButton from "./WebAuthnRegisterButton";

type WebAuthnRegistrationPageProps = {
  data: WebAuthnRegistrationPageData;
};
const WebAuthnRegistrationPage: FC<WebAuthnRegistrationPageProps> = ({
  data,
}) => {
  return (
    <Section title="WebAuthn Registration" icon={<ExperimentalIcon />}>
      <Stack direction="row" justifyContent="center" spacing={1}>
        <WebAuthnRegisterButton
          creationOptions={data?.creationOptions}
          url={data?.selfUrl}
        />
        <WebAuthnAuthenticateButton
          requestOptions={data?.requestOptions}
          url={data?.selfUrl}
        />
      </Stack>
    </Section>
  );
};
export default WebAuthnRegistrationPage;
