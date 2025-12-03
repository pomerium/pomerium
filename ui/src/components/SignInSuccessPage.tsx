import type { FC } from "react";
import type { SignInSuccessPageData } from "src/types";
import {
  Paper,
  TableContainer,
  Table,
  TableHead,
  TableBody,
  TableCell,
  TableRow,
  Button,
  Box,
} from '@mui/material'

type SignInSuccessPageProps = {
  data: SignInSuccessPageData;
};
const SignInSuccessPage: FC<SignInSuccessPageProps> = ({ data }) => {
  return (
    <>
      <TableContainer component={Paper} sx={{ maxWidth: 540, mx: "auto", mb: 2 }}>
      <Table size="small" aria-label="metadata table">
          <TableHead>
            <TableRow>
              <TableCell variant="head">Field</TableCell>
              <TableCell variant="head">Value</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <TableRow>
              <TableCell component="th" scope="row">Name</TableCell>
              <TableCell>{data.user.name}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell component="th" scope="row">Protocol</TableCell>
              <TableCell>{data.protocol}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell component="th" scope="row">Expiry date</TableCell>
              <TableCell>{data.expiresAt}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </TableContainer>
      <Box sx={{ maxWidth: 540, mx: "auto", textAlign: "center" }}>
        <Button 
          variant="contained" 
          href="/.pomerium/session_binding_info"
          sx={{ textTransform: 'none' }}
        >
          Manage client bindings
        </Button>
      </Box>
    </>
  );
};
export default SignInSuccessPage;
