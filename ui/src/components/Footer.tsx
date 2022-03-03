import Box from "@mui/material/Box";
import Stack from "@mui/material/Stack";
import React, { FC } from "react";
import {FooterLink} from "./FooterLink";
import AppBar from "@mui/material/AppBar";

type FooterData = {
  pomeriumVersion?: string;
}

const Footer: FC<FooterData> = ({pomeriumVersion}) => {
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
            href="https://discuss.pomerium.com"
          >
            Support
          </FooterLink>
        </Box>
      </Stack>
      {!!pomeriumVersion && (
        <Stack
          direction="row"
          spacing={2}
          justifyContent="center"
          sx={{
            paddingBottom: "6px",
            fontSize: "0.85rem",
          }}
        >
          <Box><b>Pomerium Version:</b> {pomeriumVersion}</Box>
        </Stack>
      )}
    </AppBar>
  );
};
export default Footer;
