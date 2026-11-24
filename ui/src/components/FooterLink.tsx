import Link from "@mui/material/Link";
import { styled } from "@mui/system";

const FooterLink = styled(Link)(({ theme }) => ({
  fontSize: "1.25rem",
  fontWeight: `bold`,
  color: theme.palette.background.default,
}));
export default FooterLink;
