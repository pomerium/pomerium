import { Stack } from "@mui/material";
import React, { FC } from "react";
import { SignInSuccessPageData } from "src/types";

type SignInSuccessPageProps = {
  data: SignInSuccessPageData;
};
const SignInSuccessPage: FC<SignInSuccessPageProps> = ({ data }) => {
  return (
    <>
      <p>success</p>
    </>
  );
};
export default SignInSuccessPage;
