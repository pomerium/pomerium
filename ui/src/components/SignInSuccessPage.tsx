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
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Link,
} from '@mui/material'

import ExpandMoreIcon from "@mui/icons-material/ExpandMore";

type SignInSuccessPageProps = {
  data: SignInSuccessPageData;
};

const SignInSuccessPage: FC<SignInSuccessPageProps> = ({ data }) => {
  return (
    <Box sx={{ maxWidth: 540, mx: "auto", textAlign: "center" }}>
      <Typography variant="h5" fontWeight="bold" gutterBottom>
        Sign in successful
      </Typography>
      <Typography variant="body2" sx={{ mb: 3 }}>
        You may now close this page
      </Typography>

      <Accordion>
        <AccordionSummary
          expandIcon={<ExpandMoreIcon />}
          sx={{
            "& .MuiAccordionSummary-content": {
              justifyContent: "center",
            },
          }}
        >
          <Typography align="center">Session details</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer component={Paper}>
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
        </AccordionDetails>
      </Accordion>

      <Box sx={{ mt: 4}}>Need to change users?
        <Link
          href="/.pomerium/session_binding_info"
          sx={{
            ml : 1,
            display: "inline-block",
            px: 2,
            py: 0.75,
            borderRadius: 1,
            bgcolor: "primary.main",
            color: "primary.contrastText",
            fontSize: "0.8125rem",
            fontWeight: 500,
            "&:hover": {
              bgcolor: "primary.dark",
            },
          }}
        >
          Manage client bindings
        </Link>
      </Box>
    </Box>
  );
};

export default SignInSuccessPage;
