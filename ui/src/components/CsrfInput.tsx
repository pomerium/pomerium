import React, { FC } from "react";

export type CsrfInputProps = {
  csrfToken: string;
};
export const CsrfInput: FC<CsrfInputProps> = ({ csrfToken }) => {
  return <input type="hidden" name="_pomerium_csrf" value={csrfToken} />;
};
export default CsrfInput;
