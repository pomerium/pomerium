import { Stack } from "@mui/material";
import React, { FC } from "react";
import { SignInVerifyPageData } from "src/types";

type SignInVerifyPageProps = {
  data: SignInVerifyPageData;
};
const SignInVerifyPage: FC<SignInVerifyPageProps> = ({ data }) => {
  return (
    <>
      <a href={data.redirectUrl}>confirm</a>
    </>
  );
};
export default SignInVerifyPage;
