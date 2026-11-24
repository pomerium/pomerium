import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import Accordion from "@mui/material/Accordion";
import AccordionDetails from "@mui/material/AccordionDetails";
import AccordionSummary from "@mui/material/AccordionSummary";
import Box from "@mui/material/Box";
import Link from "@mui/material/Link";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import type { SignInSuccessPageData } from "../types";

type SignInSuccessPageProps = {
  data: SignInSuccessPageData;
};

export default function SignInSuccessPage({ data }: SignInSuccessPageProps) {
  return (
    <Box sx={{ maxWidth: 540, mx: "auto", textAlign: "center" }}>
      <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold" }}>
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
                  <TableCell component="th" scope="row">
                    Name
                  </TableCell>
                  <TableCell>{data.user?.name}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell component="th" scope="row">
                    Protocol
                  </TableCell>
                  <TableCell>{data.protocol}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell component="th" scope="row">
                    Expiry date
                  </TableCell>
                  <TableCell>{data.expiresAt}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      <Box sx={{ mt: 4 }}>
        Need to change users?
        <Link
          href="/.pomerium/session_binding_info"
          sx={{
            ml: 1,
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
}
