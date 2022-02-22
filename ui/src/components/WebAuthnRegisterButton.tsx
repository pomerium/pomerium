import React, { FC } from "react";

import { WebAuthnCreationOptions } from "../types";
import { decode, encodeUrl } from "../util/base64";
import WebAuthnButton, { WebAuthnButtonProps } from "./WebAuthnButton";

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
          creationOptions?.authenticatorSelection?.userVerification ||
          undefined,
      },
      challenge: decode(creationOptions?.challenge),
      pubKeyCredParams: creationOptions?.pubKeyCredParams?.map((p) => ({
        type: p.type,
        alg: p.alg,
      })),
      rp: {
        name: creationOptions?.rp?.name,
      },
      timeout: creationOptions?.timeout,
      user: {
        id: decode(creationOptions?.user?.id),
        name: creationOptions?.user?.name,
        displayName: creationOptions?.user?.displayName,
      },
    },
  });
  return credential as CredentialForCreate;
}

export type WebAuthnRegisterButtonProps = Omit<
  WebAuthnButtonProps,
  "action" | "enable" | "onClick" | "text"
> & {
  creationOptions: WebAuthnCreationOptions;
  csrfToken: string;
  url: string;
};
export const WebAuthnRegisterButton: FC<WebAuthnRegisterButtonProps> = ({
  creationOptions,
  ...props
}) => {
  async function register(): Promise<unknown> {
    const credential = await createCredential(creationOptions);
    return {
      id: credential.id,
      type: credential.type,
      rawId: encodeUrl(credential.rawId),
      response: {
        attestationObject: encodeUrl(credential.response.attestationObject),
        clientDataJSON: encodeUrl(credential.response.clientDataJSON),
      },
    };
  }

  return (
    <WebAuthnButton
      action="register"
      enable={!!creationOptions}
      onClick={register}
      text={"Register New Device"}
      {...props}
    />
  );
};
export default WebAuthnRegisterButton;
