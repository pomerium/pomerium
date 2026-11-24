import Alert from "@mui/material/Alert";
import Container from "@mui/material/Container";

import type { SignedOutPageData } from "../types";

type SignedOutPageProps = {
  data: SignedOutPageData;
};
export default function SignedOutPage(_props: SignedOutPageProps) {
  return (
    <Container>
      <Alert color="info">User has been logged out.</Alert>
    </Container>
  );
}
