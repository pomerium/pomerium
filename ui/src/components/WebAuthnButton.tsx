import Button, { ButtonProps } from "@mui/material/Button";
import React, { FC, useRef, useState } from "react";

import AlertDialog from "./AlertDialog";

export type WebAuthnButtonProps = Omit<ButtonProps, "action"> & {
  action: string;
  csrfToken: string;
  enable: boolean;
  onClick: () => Promise<unknown>;
  text: string;
  url: string;
};
export const WebAuthnButton: FC<WebAuthnButtonProps> = ({
  action,
  csrfToken,
  enable,
  onClick,
  text,
  url,
  ...props
}) => {
  const formRef = useRef<HTMLFormElement>();
  const responseRef = useRef<HTMLInputElement>();
  const [error, setError] = useState<string>(null);

  function handleClickButton(evt: React.MouseEvent): void {
    evt.preventDefault();

    void (async () => {
      try {
        const response = await onClick();
        responseRef.current.value = JSON.stringify(response);
        formRef.current.submit();
      } catch (e) {
        setError(`${e}`);
      }
    })();
  }
  function handleClickDialogOK(evt: React.MouseEvent): void {
    evt.preventDefault();
    setError(null);
  }

  return (
    <>
      <Button
        onClick={handleClickButton}
        variant="contained"
        disabled={!enable}
        {...props}
      >
        {text}
      </Button>
      <form ref={formRef} method="post" action={url}>
        <input type="hidden" name="_pomerium_csrf" value={csrfToken} />
        <input type="hidden" name="action" value={action} />
        <input type="hidden" name={action + "_response"} ref={responseRef} />
      </form>
      <AlertDialog
        title="Error"
        severity="error"
        open={!!error}
        actions={<Button onClick={handleClickDialogOK}>OK</Button>}
      >
        {error}
      </AlertDialog>
    </>
  );
};
export default WebAuthnButton;
