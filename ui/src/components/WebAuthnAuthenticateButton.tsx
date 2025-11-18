import type { FC } from "react";
import React from "react";

import type { WebAuthnRequestOptions } from "../types";
import { decode, encodeUrl } from "../util/base64";
import type { WebAuthnButtonProps } from "./WebAuthnButton";
import WebAuthnButton from "./WebAuthnButton";

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
        id: decode(c.id),
      })),
      challenge: decode(requestOptions?.challenge),
      timeout: requestOptions?.timeout,
      userVerification: requestOptions?.userVerification,
      rpId: requestOptions?.rpId,
    },
  });
  return credential as CredentialForAuthenticate;
}

export type WebAuthnAuthenticateButtonProps = Omit<
  WebAuthnButtonProps,
  "action" | "enable" | "onClick" | "text"
> & {
  requestOptions: WebAuthnRequestOptions;
};
export const WebAuthnAuthenticateButton: FC<
  WebAuthnAuthenticateButtonProps
> = ({ requestOptions, ...props }) => {
  async function authenticate(): Promise<unknown> {
    const credential = await authenticateCredential(requestOptions);
    return {
      id: credential.id,
      type: credential.type,
      rawId: encodeUrl(credential.rawId),
      response: {
        authenticatorData: encodeUrl(credential.response.authenticatorData),
        clientDataJSON: encodeUrl(credential.response.clientDataJSON),
        signature: encodeUrl(credential.response.signature),
        userHandle: encodeUrl(credential.response.userHandle),
      },
    };
  }

  return (
    <WebAuthnButton
      action="authenticate"
      enable={requestOptions?.allowCredentials?.length > 0}
      onClick={authenticate}
      text={"Authenticate Existing Device"}
      {...props}
    />
  );
};
export default WebAuthnAuthenticateButton;
