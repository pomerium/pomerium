import Box from "@mui/material/Box";
import Container from "@mui/material/Container";
import Stack from "@mui/material/Stack";
import React, { FC } from "react";

const Footer: FC = () => {
  return (
    <Container component="footer">
      <Stack
        direction="row"
        spacing={2}
        sx={{
          fontSize: "0.85rem",
          padding: "16px"
        }}
      >
        <Box>
          <a href="https://pomerium.com/">Home</a>
        </Box>
        <Box>
          <a href="https://pomerium.com/docs">Docs</a>
        </Box>
        <Box>
          <a href="https://pomerium.com/docs/community/">Support</a>
        </Box>
        <Box>
          <a href="https://github.com/pomerium">GitHub</a>
        </Box>
        <Box>
          <a href="https://twitter.com/pomerium_io">@pomerium_io</a>
        </Box>
        <Box flexGrow={1} sx={{ textAlign: "right" }}>
          © Pomerium, Inc.
        </Box>
      </Stack>
    </Container>
  );
};
export default Footer;
