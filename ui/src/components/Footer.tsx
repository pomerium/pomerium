import Box from "@mui/material/Box";
import Stack from "@mui/material/Stack";
import React, { FC } from "react";
import {FooterLink} from "./FooterLink";
import AppBar from "@mui/material/AppBar";

const Footer: FC = () => {
  return (
    <AppBar
      position="fixed"
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 1,
        top: 'auto',
        bottom: 0,
      }}
    >
      <Stack
        direction="row"
        spacing={2}
        sx={{
          fontSize: "0.85rem",
          padding: "16px",
          paddingLeft: "32px",
          paddingRight: "32px"
        }}
      >
        <Box>
          <FooterLink
            href="https://pomerium.com/"
          >
            Home
          </FooterLink>
        </Box>
        <Box>
          <FooterLink
            href="https://pomerium.com/docs"
          >
            Docs
          </FooterLink>
        </Box>
        <Box>
          <FooterLink
            href="https://pomerium.com/docs/community/"
          >
            Support
          </FooterLink>
        </Box>
        <Box>
          <FooterLink
            href="https://github.com/pomerium"
          >
            Github
          </FooterLink>
        </Box>
        <Box>
          <FooterLink
            href="https://twitter.com/pomerium_io"
          >
            @pomerium_io
          </FooterLink>
        </Box>
        <Box flexGrow={1} sx={{ textAlign: "right" }}>
          © Pomerium, Inc.
        </Box>
      </Stack>
    </AppBar>
  );
};
export default Footer;
