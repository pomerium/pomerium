import { Alert, Container } from "@mui/material";
import React, { FC } from "react";

import { SignedOutPageData } from "../types";

type SignedOutPageProps = {
  data: SignedOutPageData;
};
const SignedOutPage: FC<SignedOutPageProps> = ({ data }) => {
  return (
    <Container>
      <Alert color="info">User has been logged out.</Alert>
    </Container>
  );
};
export default SignedOutPage;
