import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Stack from "@mui/material/Stack";
import React, { FC } from "react";

import { FooterLink } from "./FooterLink";

const Footer: FC = () => {
  return (
    <AppBar
      position="fixed"
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 1,
        top: "auto",
        bottom: 0,
      }}
    >
      <Stack
        direction="row"
        spacing={8}
        justifyContent="center"
        sx={{
          fontSize: "0.85rem",
          paddingLeft: "16px",
          paddingRight: "16px",
          paddingBottom: "8px",
          paddingTop: "16px",
        }}
      >
        <Box>
          <FooterLink href="https://pomerium.com/">Home</FooterLink>
        </Box>
        <Box>
          <FooterLink href="https://pomerium.com/docs">Docs</FooterLink>
        </Box>
        <Box>
          <FooterLink href="https://discuss.pomerium.com">Support</FooterLink>
        </Box>
      </Stack>
    </AppBar>
  );
};
export default Footer;
