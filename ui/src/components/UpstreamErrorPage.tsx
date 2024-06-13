import { CheckCircleRounded, Circle } from "@mui/icons-material";
import {
  Alert,
  AlertTitle,
  Card,
  CardContent,
  Container,
  Divider,
  Link,
  Stack,
  Typography,
} from "@mui/material";
import React, { FC } from "react";

import { ErrorPageProps } from "./ErrorPage";

export const UpstreamErrorPage: FC<ErrorPageProps> = ({ data }) => {
  const status = data?.status || 500;
  console.log(data.statusText);
  return (
    <Container>
      <Card>
        <Alert severity="error" sx={{ borderRadius: 0 }}>
          <AlertTitle>
            <Typography variant="h3">Error {status}</Typography>
          </AlertTitle>
          <Typography variant="body2">Web Server is down</Typography>
        </Alert>

        <Divider sx={{ color: "rgba(234, 236, 240, 1)" }} />

        <Card sx={{ borderRadius: 0, borderTop: 0 }}>
          <Stack
            direction="row"
            alignItems="center"
            width="100%"
            sx={{
              m: "3vw",
            }}
            gap={15}
          >
            <Stack direction="row" alignItems="center" gap={2}>
              <CheckCircleRounded color="primary" fontSize="large" />
              <Stack>
                <Typography variant="overline">YOU (BROWSER)</Typography>
                <Typography color="primary.main" variant="body2">
                  Working
                </Typography>
              </Stack>
            </Stack>

            <Divider
              sx={{
                color: "primary.main",
                width: "2vw",
                height: 1,
                border: 1,
              }}
            />

            <Stack direction="row" alignItems="center" gap={2}>
              <CheckCircleRounded color="primary" fontSize="large" />
              <Stack>
                <Typography variant="overline">POMERIUM</Typography>
                <Typography color="primary.main" variant="body2">
                  Working
                </Typography>
              </Stack>
            </Stack>

            <Divider
              sx={{
                color: "rgba(234, 236, 240, 1)",
                width: "2vw",
                height: 1,
                border: 1,
              }}
            />

            <Stack direction="row" alignItems="center" gap={2}>
              <Circle color="error" fontSize="large" />
              <Stack>
                <Typography variant="overline">UPSTREAM HOST</Typography>
                <Typography color="error" variant="body2">
                  Error
                </Typography>
              </Stack>
            </Stack>
          </Stack>
          <CardContent>
            <Divider sx={{ color: "rgba(234, 236, 240, 1)" }} />
            <Stack gap={1} sx={{ my: 5 }}>
              <Typography variant="h5">What happened?</Typography>
              <Typography variant="body2" color="rgba(102, 112, 133, 1)">
                The web server is not returning a connection. As a result, the
                webpage is not displaying.
              </Typography>
            </Stack>
            <Divider sx={{ color: "rgba(234, 236, 240, 1)" }} />
            <Stack gap={2} sx={{ my: 5 }}>
              <Stack gap={1}>
                <Typography variant="h5">What can I do?</Typography>
              </Stack>
              <Stack>
                <Typography variant="body2" fontWeight={700} color="rgba(102, 112, 133, 1)">
                  If you are a visitor of this website:
                </Typography>
                <Typography variant="body2" fontWeight={400} color="rgba(102, 112, 133, 1)">
                  Please try again in a few minutes.
                </Typography>
              </Stack>
              <Stack>
                <Typography variant="body2" fontWeight={700}>
                  If you are the owner of this website:
                </Typography>
                <Typography variant="body2" fontWeight={400} color="rgba(102, 112, 133, 1)">
                  Contact your hosting provider letting them know your web
                  server is not responding.
                </Typography>
                <Typography variant="body2" fontWeight={400} color="rgba(102, 112, 133, 1)">
                  Error Text: {data.statusText}
                </Typography>
                <Link
                    href="https://www.pomerium.com/docs/troubleshooting#envoy-error-messages"
                    underline="hover"
                    color="primary.main"
                    variant="body2"
                    target="_blank"
                >
                  Additional troubleshooting information.
                </Link>
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      </Card>
    </Container>
  );
};
export default UpstreamErrorPage;
