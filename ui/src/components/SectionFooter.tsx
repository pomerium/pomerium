import { Box, styled } from "@mui/material";
import React, { FC } from "react";

export const SectionFooter = styled(Box)(({ theme }) => ({
  backgroundColor: theme.palette.grey[100],
  padding: theme.spacing(3),
}));
export default SectionFooter;
