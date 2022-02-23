import { decode, encodeUrl } from "../util/base64";
import AlertDialog from "./AlertDialog";
import ExperimentalIcon from "./ExperimentalIcon";
import HeroSection from "./HeroSection";
import Button from "@mui/material/Button";
import Container from "@mui/material/Container";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import React, { FC, useRef, useState } from "react";
import {
  WebAuthnCreationOptions,
  WebAuthnRegistrationPageData,
  WebAuthnRequestOptions
} from "src/types";
import JwtIcon from "./JwtIcon";
import ClaimsTable from "./ClaimsTable";
import Section from "./Section";

type CredentialForAuthenticate = {
  id: string;
  type: string;
  rawId: ArrayBuffer;
  response: {
    authenticatorData: ArrayBuffer;
    clientDataJSON: ArrayBuffer;
    signature: ArrayBuffer;
    userHandle: ArrayBuffer;
  };
};

async function authenticateCredential(
  requestOptions: WebAuthnRequestOptions
): Promise<CredentialForAuthenticate> {
  const credential = await navigator.credentials.get({
    publicKey: {
      allowCredentials: requestOptions?.allowCredentials?.map((c) => ({
        type: c.type,
        id: decode(c.id)
      })),
      challenge: decode(requestOptions?.challenge),
      timeout: requestOptions?.timeout,
      userVerification: requestOptions?.userVerification
    }
  });
  return credential as CredentialForAuthenticate;
}

type CredentialForCreate = {
  id: string;
  type: string;
  rawId: ArrayBuffer;
  response: {
    attestationObject: ArrayBuffer;
    clientDataJSON: ArrayBuffer;
  };
};

async function createCredential(
  creationOptions: WebAuthnCreationOptions
): Promise<CredentialForCreate> {
  const credential = await navigator.credentials.create({
    publicKey: {
      attestation: creationOptions?.attestation || undefined,
      authenticatorSelection: {
        authenticatorAttachment:
          creationOptions?.authenticatorSelection?.authenticatorAttachment ||
          undefined,
        requireResidentKey:
          creationOptions?.authenticatorSelection?.requireResidentKey ||
          undefined,
        residentKey: creationOptions?.authenticatorSelection?.residentKey,
        userVerification:
          creationOptions?.authenticatorSelection?.userVerification || undefined
      },
      challenge: decode(creationOptions?.challenge),
      pubKeyCredParams: creationOptions?.pubKeyCredParams?.map((p) => ({
        type: p.type,
        alg: p.alg
      })),
      rp: {
        name: creationOptions?.rp?.name
      },
      timeout: creationOptions?.timeout,
      user: {
        id: decode(creationOptions?.user?.id),
        name: creationOptions?.user?.name,
        displayName: creationOptions?.user?.displayName
      }
    }
  });
  return credential as CredentialForCreate;
}

type WebAuthnRegistrationPageProps = {
  data: WebAuthnRegistrationPageData;
};
const WebAuthnRegistrationPage: FC<WebAuthnRegistrationPageProps> = ({
  data
}) => {
  const authenticateFormRef = useRef<HTMLFormElement>();
  const authenticateResponseRef = useRef<HTMLInputElement>();
  const registerFormRef = useRef<HTMLFormElement>();
  const registerResponseRef = useRef<HTMLInputElement>();

  const [error, setError] = useState<string>(null);

  const enableAuthenticate = data?.requestOptions?.allowCredentials?.length > 0;

  function handleClickAuthenticate(evt: React.MouseEvent): void {
    evt.preventDefault();

    void (async () => {
      try {
        const credential = await authenticateCredential(data?.requestOptions);
        authenticateResponseRef.current.value = JSON.stringify({
          id: credential.id,
          type: credential.type,
          rawId: encodeUrl(credential.rawId),
          response: {
            authenticatorData: encodeUrl(credential.response.authenticatorData),
            clientDataJSON: encodeUrl(credential.response.clientDataJSON),
            signature: encodeUrl(credential.response.signature),
            userHandle: encodeUrl(credential.response.userHandle)
          }
        });
        authenticateFormRef.current.submit();
      } catch (e) {
        setError(`${e}`);
      }
    })();
  }
  function handleClickDialogOK(evt: React.MouseEvent): void {
    evt.preventDefault();
    setError(null);
  }
  function handleClickRegister(evt: React.MouseEvent): void {
    evt.preventDefault();

    void (async () => {
      try {
        const credential = await createCredential(data?.creationOptions);
        registerResponseRef.current.value = JSON.stringify({
          id: credential.id,
          type: credential.type,
          rawId: encodeUrl(credential.rawId),
          response: {
            attestationObject: encodeUrl(credential.response.attestationObject),
            clientDataJSON: encodeUrl(credential.response.clientDataJSON)
          }
        });
        registerFormRef.current.submit();
      } catch (e) {
        setError(`${e}`);
      }
    })();
  }

  return (
    <Section title="WebAuthn Registration" icon={<ExperimentalIcon />}>
      <Paper sx={{ padding: "16px" }}>
        <Stack direction="row" justifyContent="center" spacing={3}>
          <Button onClick={handleClickRegister} variant="contained">
            Register New Device
          </Button>
          <Button
            onClick={handleClickAuthenticate}
            variant="contained"
            disabled={!enableAuthenticate}
          >
            Authenticate Existing Device
          </Button>
        </Stack>
      </Paper>
      <form ref={authenticateFormRef} method="post" action={data?.selfUrl}>
        <input type="hidden" name="_pomerium_csrf" value={data?.csrfToken} />
        <input type="hidden" name="action" value="authenticate" />
        <input
          type="hidden"
          name="authenticate_response"
          ref={authenticateResponseRef}
        />
      </form>
      <form ref={registerFormRef} method="POST" action={data?.selfUrl}>
        <input type="hidden" name="_pomerium_csrf" value={data?.csrfToken} />
        <input type="hidden" name="action" value="register" />
        <input
          type="hidden"
          name="register_response"
          ref={registerResponseRef}
        />
      </form>
      <AlertDialog
        title="Error"
        severity="error"
        open={!!error}
        actions={<Button onClick={handleClickDialogOK}>OK</Button>}
      >
        {error}
      </AlertDialog>
    </Section>
  );
};
export default WebAuthnRegistrationPage;
