import * as React from 'react';
import { styled } from '@mui/system';
import {Link} from "@mui/material";

export const FooterLink = styled(Link)(({ theme }) => ({
  fontSize: '1.25rem',
  fontWeight: `bold`,
  color: theme.palette.background.default,
}));
export default FooterLink;
