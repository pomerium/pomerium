import { Button, Stack } from "@mui/material";
import React, { FC, useState, useEffect } from "react";
import { SignInVerifyPageData } from "src/types";


import {
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  FormControlLabel,
  Box,
  Checkbox,
  Typography,
} from "@mui/material";

type SignInVerifyPageProps = {
  data: SignInVerifyPageData;
};
const SignInVerifyPage: FC<SignInVerifyPageProps> = ({ data }) => {
  const parseToDate = (v: any): Date => {
    if (v instanceof Date && !isNaN(v.getTime())) return v;
    if (typeof v === "number" && !isNaN(v)) return new Date(v);
    if (typeof v === "string") {
      const parsed = Date.parse(v);
      if (!isNaN(parsed)) return new Date(parsed);
    }
    return new Date(Date.now() + 2 * 60 * 1000);
  };

  const expiresDate = parseToDate((data as any).expiresAt ?? data.expiresAt);
  const [remainingSeconds, setRemainingSeconds] = useState<number>(
    Math.max(0, Math.round((expiresDate.getTime() - Date.now()) / 1000))
  );


  useEffect(() => {
    const id = setInterval(() => {
      const secs = Math.max(0, Math.round((expiresDate.getTime() - Date.now()) / 1000));
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

  return (
    <>
      <TableContainer component={Paper} sx={{ maxWidth: 540, mx: "auto", mb: 2 }}>
        <Table size="small" aria-label="metadata table">
          <TableHead>
            <TableRow>
              <TableCell variant="head">Field</TableCell>
              <TableCell variant="head" align="left">Value</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <TableRow>
              <TableCell component="th" scope="row">Protocol</TableCell>
              <TableCell align="left">{data.protocol}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell component="th" scope="row">Issued at</TableCell>
              <TableCell align="left">{parseToDate(data.issuedAt).toLocaleString()}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell component="th" scope="row">Initiated from</TableCell>
              <TableCell align="left">{data.sourceAddr}</TableCell>
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
            bgcolor: (t) => (remainingSeconds === 0 ? t.palette.error.light : t.palette.primary.light),
            color: (t) => t.palette.getContrastText(remainingSeconds === 0 ? t.palette.error.light : t.palette.primary.light),
            boxShadow: 1,
            mb: 1,
          }}
          aria-live="polite"
        >
          <Typography variant="subtitle2" sx={{ mr: 1 }}>
            Expires in
          </Typography>
          <Typography variant="h6" component="span" sx={{ fontVariantNumeric: "tabular-nums", fontWeight: 600 }}>
            {formatMMSS(remainingSeconds)}
          </Typography>
        </Box>
      </Box>
      <Box sx={{ maxWidth: 540, mx: "auto", px: 2 }}>
        <Box sx={{ display: "flex", justifyContent: "center", mb: 1 }}>
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
        </Box>

        <Stack direction="row" justifyContent="center" spacing={2} alignItems="center">
          <Box
            component="form"
            action={data.redirectUrl}
            method="POST"
            sx={{ display: "inline-flex", gap: 1 }}
          >
            <input type="hidden" name="confirm" value="false" />
            <Button size="small" type="submit" variant="contained">
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
            <Button size="small" type="submit" variant="contained">
              Authorize
            </Button>
          </Box>
        </Stack>
      </Box>
    </>
  );
};
export default SignInVerifyPage;
