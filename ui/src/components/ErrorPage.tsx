import { ErrorPageData } from "../types";
import SectionFooter from "./SectionFooter";
import Alert from "@mui/material/Alert";
import AlertTitle from "@mui/material/AlertTitle";
import Box from "@mui/material/Box";
import Container from "@mui/material/Container";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import React, { FC } from "react";

export type ErrorPageProps = {
  data: ErrorPageData;
};
export const ErrorPage: FC<ErrorPageProps> = ({ data }) => {
  return (
    <Container>
      <Paper sx={{ overflow: "hidden" }}>
        <Stack>
          <Box sx={{ padding: "16px" }}>
            <Alert severity="error">
              <AlertTitle>
                {data?.status || 500}{" "}
                {data?.statusText || "Internal Server Error"}
              </AlertTitle>
              {data?.error || "Internal Server Error"}
            </Alert>
          </Box>
          {data?.requestId ? (
            <SectionFooter>
              <Typography variant="caption">
                If you should have access, contact your administrator with your
                request id {data?.requestId}.
              </Typography>
            </SectionFooter>
          ) : (
            <></>
          )}
        </Stack>
      </Paper>
    </Container>
  );
};
export default ErrorPage;
