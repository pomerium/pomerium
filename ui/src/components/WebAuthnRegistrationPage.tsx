import Stack from "@mui/material/Stack";

import type { WebAuthnRegistrationPageData } from "../types";
import ExperimentalIcon from "./ExperimentalIcon";
import Section from "./Section";
import WebAuthnAuthenticateButton from "./WebAuthnAuthenticateButton";
import WebAuthnRegisterButton from "./WebAuthnRegisterButton";

type WebAuthnRegistrationPageProps = {
  data: WebAuthnRegistrationPageData;
};
export default function WebAuthnRegistrationPage({ data }: WebAuthnRegistrationPageProps) {
  return (
    <Section title="WebAuthn Registration" icon={<ExperimentalIcon />}>
      <Stack direction="row" spacing={1} sx={{ justifyContent: "center" }}>
        <WebAuthnRegisterButton creationOptions={data?.creationOptions} url={data?.selfUrl} />
        <WebAuthnAuthenticateButton requestOptions={data?.requestOptions} url={data?.selfUrl} />
      </Stack>
    </Section>
  );
}
