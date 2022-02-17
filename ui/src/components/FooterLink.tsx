import * as React from 'react';
import { styled } from '@mui/system';
import {Link} from "@mui/material";

export const FooterLink = styled(Link)(({ theme }) => ({
  fontWeight: `bold`,
  color: theme.palette.text.secondary
}));