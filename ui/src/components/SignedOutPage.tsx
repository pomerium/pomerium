import { Alert, Container } from "@mui/material";
import type { FC } from "react";
import React from "react";

import type { SignedOutPageData } from "../types";

type SignedOutPageProps = {
  data: SignedOutPageData;
};
const SignedOutPage: FC<SignedOutPageProps> = () => {
  return (
    <Container>
      <Alert color="info">User has been logged out.</Alert>
    </Container>
  );
};
export default SignedOutPage;
