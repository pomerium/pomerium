import { Alert } from "@mui/material";
import Container from "@mui/material/Container";
import React, { FC } from "react";
import { SignedOutPageData } from "src/types";

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
