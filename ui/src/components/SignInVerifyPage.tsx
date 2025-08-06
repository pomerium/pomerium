import { Button, Stack } from "@mui/material";
import React, { FC } from "react";
import { SignInVerifyPageData } from "src/types";

type SignInVerifyPageProps = {
  data: SignInVerifyPageData;
};
const SignInVerifyPage: FC<SignInVerifyPageProps> = ({ data }) => {
  return (
    <Stack direction="row" justifyContent="center" spacing={1}>
      <form action={data.redirectUrl} method="POST">
        <input type="hidden" name="_pomerium_csrf" value={data.csrfToken} />
        <input type="hidden" name="confirm" value="false" />
        <Button size="small" type="submit" variant="contained">
          Cancel
        </Button>
      </form>

      <br />

      <form action={data.redirectUrl} method="POST">
        <input type="hidden" name="_pomerium_csrf" value={data.csrfToken} />
        <input type="hidden" name="confirm" value="true" />
        <input
          id="create-id-binding"
          type="checkbox"
          value="true"
          name="create_id_binding"
        />
        <label htmlFor="create-id-binding"> remember me</label>
        <Button size="small" type="submit" variant="contained">
          Authorize
        </Button>
      </form>
    </Stack>
  );
};
export default SignInVerifyPage;
