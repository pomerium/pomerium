import type { ListItemProps } from "@mui/material";
import {
  Alert,
  AlertTitle,
  Box,
  Container,
  Paper,
  Stack,
  Table,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import Markdown from "markdown-to-jsx";
import type { FC } from "react";
import React from "react";
import { CheckCircle, MinusCircle, XCircle } from "react-feather";

import type { ErrorPageData, PolicyEvaluationTrace } from "../types";
import SectionFooter from "./SectionFooter";

type PolicyEvaluationTraceDetailsProps = {
  trace: PolicyEvaluationTrace;
} & ListItemProps;
const PolicyEvaluationTraceDetails: FC<PolicyEvaluationTraceDetailsProps> = ({
  trace,
}) => {
  return (
    <TableRow>
      <TableCell align={"center"}>
        {trace.deny ? (
          <XCircle color="red" />
        ) : trace.allow ? (
          <CheckCircle color="green" />
        ) : (
          <MinusCircle color="gray" />
        )}
      </TableCell>
      <TableCell>
        <Markdown>{trace.explanation || `Policy ID ${trace.id}`}</Markdown>
      </TableCell>
      <TableCell>
        <Markdown>
          {trace.deny || !trace.allow ? trace.remediation : ""}
        </Markdown>
      </TableCell>
    </TableRow>
  );
};

export type ErrorPageProps = {
  data: ErrorPageData;
};
export const ErrorPage: FC<ErrorPageProps> = ({ data }) => {
  const traces =
    data?.policyEvaluationTraces?.filter((trace) => !!trace.id) || [];
  const status = data?.status || 500;

  return (
    <Container maxWidth={false}>
      <Paper sx={{ overflow: "hidden" }}>
        <Stack>
          <Box sx={{ padding: "16px" }}>
            <Alert
              severity={status < 200 || status >= 300 ? "error" : "success"}
            >
              <AlertTitle>
                {status} {data?.statusText || "Internal Server Error"}
              </AlertTitle>
              {data?.description ? (
                <Markdown>{data.description}</Markdown>
              ) : (
                <></>
              )}
            </Alert>
          </Box>
          {!!data?.errorMessageFirstParagraph && (
            <Box sx={{ p: 4 }}>
              <Markdown>{data.errorMessageFirstParagraph}</Markdown>
            </Box>
          )}
          {traces?.length > 0 && (
            <Container>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Outcome</TableCell>
                    <TableCell>Explanation</TableCell>
                    <TableCell>Remediation</TableCell>
                  </TableRow>
                </TableHead>
                {traces.map((trace) => (
                  <PolicyEvaluationTraceDetails trace={trace} key={trace.id} />
                ))}
              </Table>
            </Container>
          )}
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
