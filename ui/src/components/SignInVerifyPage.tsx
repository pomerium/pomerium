import { Button, Stack } from "@mui/material";
import {
  Box,
  Checkbox,
  FormControlLabel,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import type { FC } from "react";
import React, { useEffect, useState } from "react";
import type { SignInVerifyPageData } from "src/types";

import { SmallTooltip } from "./Tooltips";

type SignInVerifyPageProps = {
  data: SignInVerifyPageData;
};
const SignInVerifyPage: FC<SignInVerifyPageProps> = ({ data }) => {
  const parseToDate = (v: unknown): Date => {
    if (v instanceof Date && !isNaN(v.getTime())) return v;
    if (typeof v === "number" && !isNaN(v)) return new Date(v);
    if (typeof v === "string") {
      const parsed = Date.parse(v);
      if (!isNaN(parsed)) return new Date(parsed);
    }
    return new Date(Date.now() + 2 * 60 * 1000);
  };

  const expiresDate = parseToDate(data.expiresAt);
  const [remainingSeconds, setRemainingSeconds] = useState<number>(
    Math.max(0, Math.round((expiresDate.getTime() - Date.now()) / 1000))
  );

  useEffect(() => {
    const id = setInterval(() => {
      const secs = Math.max(
        0,
        Math.round((expiresDate.getTime() - Date.now()) / 1000)
      );
      setRemainingSeconds(secs);
    }, 1000);
    return () => clearInterval(id);
  }, [expiresDate]);

  const formatMMSS = (secs: number) => {
    const m = Math.floor(secs / 60)
      .toString()
      .padStart(2, "0");
    const s = Math.floor(secs % 60)
      .toString()
      .padStart(2, "0");
    return `${m}:${s}`;
  };

  const disabled = remainingSeconds === 0;

  return (
    <>
      <TableContainer
        component={Paper}
        sx={{ maxWidth: 540, mx: "auto", mb: 2 }}
      >
        <Table size="small" aria-label="metadata table">
          <TableHead>
            <TableRow>
              <TableCell variant="head">Field</TableCell>
              <TableCell variant="head">Value</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <TableRow>
              <TableCell component="th" scope="row">
                Protocol
              </TableCell>
              <TableCell>{data.protocol}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell component="th" scope="row">
                Issued at
              </TableCell>
              <TableCell>
                {parseToDate(data.issuedAt).toLocaleString()}
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell component="th" scope="row">
                Initiated from
              </TableCell>
              <TableCell>{data.sourceAddr}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </TableContainer>
      <Box sx={{ maxWidth: 540, mx: "auto", mb: 2, textAlign: "center" }}>
        <Box
          sx={{
            display: "inline-flex",
            alignItems: "center",
            px: 2,
            py: 0.5,
            borderRadius: 2,
            bgcolor: (t) =>
              remainingSeconds === 0
                ? t.palette.error.light
                : t.palette.primary.light,
            color: (t) =>
              t.palette.getContrastText(
                remainingSeconds === 0
                  ? t.palette.error.light
                  : t.palette.primary.light
              ),
            boxShadow: 1,
            mb: 1,
          }}
          aria-live="polite"
        >
          <Typography variant="subtitle2" sx={{ mr: 1 }}>
            Expires in
          </Typography>
          <Typography
            variant="h6"
            component="span"
            sx={{
              fontFamily: "monospace",
              fontVariantNumeric: "tabular-nums",
              fontWeight: 600,
            }}
          >
            {formatMMSS(remainingSeconds)}
          </Typography>
        </Box>
      </Box>
      <Box sx={{ maxWidth: 540, mx: "auto", px: 2 }}>
        <Box
          sx={{
            display: "flex",
            flexDirection: "row",
            justifyContent: "center",
            mb: 1,
          }}
        >
          <FormControlLabel
            control={
              <Checkbox
                id="create-id-binding"
                name="create_id_binding"
                value="true"
                size="small"
                inputProps={{ form: "authorize-form" }}
              />
            }
            label="Remember me"
          />
          <SmallTooltip description="When enabled, your client is persistently bound to your user. This can be undone later" />
        </Box>

        <Stack
          direction="row"
          justifyContent="center"
          spacing={2}
          alignItems="center"
        >
          <Box
            component="form"
            action={data.redirectUrl}
            method="POST"
            sx={{ display: "inline-flex", gap: 1 }}
          >
            <input type="hidden" name="confirm" value="false" />
            <Button
              size="small"
              type="submit"
              variant="contained"
              disabled={disabled}
            >
              Deny
            </Button>
          </Box>

          <Box
            component="form"
            id="authorize-form"
            action={data.redirectUrl}
            method="POST"
            sx={{ display: "inline-flex", gap: 1, alignItems: "center" }}
          >
            <input type="hidden" name="confirm" value="true" />
            <Button
              size="small"
              type="submit"
              variant="contained"
              disabled={disabled}
            >
              Authorize
            </Button>
          </Box>
        </Stack>
      </Box>
    </>
  );
};
export default SignInVerifyPage;
