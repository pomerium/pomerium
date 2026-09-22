import { Alert, AlertTitle, Container } from "@mui/material";
import type { FC } from "react";
import React from "react";

import type { AgenticApproveResultPageData } from "../types";

type AgenticApproveResultPageProps = {
  data: AgenticApproveResultPageData;
};
const AgenticApproveResultPage: FC<AgenticApproveResultPageProps> = ({
  data,
}) => (
  <Container maxWidth="md">
    <Alert severity={data.severity}>
      <AlertTitle>{data.title}</AlertTitle>
      {data.message}
    </Alert>
  </Container>
);
export default AgenticApproveResultPage;
