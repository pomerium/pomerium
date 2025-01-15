import { Box, Container, Drawer, useMediaQuery, useTheme } from "@mui/material";
import React, { FC } from "react";

import { ToolbarOffset } from "./ToolbarOffset";
import UserSidebarContent from "./UserSidebarContent";

const SidebarPage: FC = ({ children }) => {
  const theme = useTheme();
  const mdUp = useMediaQuery(() => theme.breakpoints.up("md"), {
    defaultMatches: true,
    noSsr: false,
  });

  return (
    <Container maxWidth={false}>
      {mdUp && (
        <Drawer
          anchor="left"
          open
          PaperProps={{
            sx: {
              backgroundColor: "neutral.900",
              width: 256,
              height: "100vh",
            },
          }}
          variant="persistent"
        >
          <ToolbarOffset />
          <UserSidebarContent close={null} />
          <ToolbarOffset />
        </Drawer>
      )}
      <Box
        sx={{
          marginLeft: mdUp ? "256px" : "0px",
        }}
      >
        {children}
      </Box>
    </Container>
  );
};
export default SidebarPage;
