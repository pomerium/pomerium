import type { ButtonProps } from "@mui/material/Button";
import Button from "@mui/material/Button";
import type { MouseEvent } from "react";
import { useRef, useState } from "react";

import AlertDialog from "./AlertDialog";

export type WebAuthnButtonProps = Omit<ButtonProps, "action"> & {
  action: string;
  enable: boolean;
  onClick: () => Promise<unknown>;
  text: string;
  url: string;
};
export default function WebAuthnButton({
  action,
  enable,
  onClick,
  text,
  url,
  ...props
}: WebAuthnButtonProps) {
  const formRef = useRef<HTMLFormElement>(null);
  const responseRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);

  function handleClickButton(evt: MouseEvent): void {
    evt.preventDefault();

    void (async () => {
      try {
        const response = await onClick();
        if (responseRef.current) {
          responseRef.current.value = JSON.stringify(response);
        }
        formRef.current?.submit();
      } catch (e) {
        setError(`${e}`);
      }
    })();
  }
  function handleClickDialogOK(evt: MouseEvent): void {
    evt.preventDefault();
    setError(null);
  }

  return (
    <>
      <Button onClick={handleClickButton} variant="contained" disabled={!enable} {...props}>
        {text}
      </Button>
      <form ref={formRef} method="post" action={url}>
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
}
