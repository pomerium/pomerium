import Box from "@mui/material/Box";
import Container from "@mui/material/Container";
import Drawer from "@mui/material/Drawer";
import { useTheme } from "@mui/material/styles";
import useMediaQuery from "@mui/material/useMediaQuery";
import type { ReactNode } from "react";

import type { SidebarData } from "../types";
import ToolbarOffset from "./ToolbarOffset";
import UserSidebarContent from "./UserSidebarContent";

type SidebarPageProps = {
  children?: ReactNode;
  data?: SidebarData;
};

export default function SidebarPage({ children, data }: SidebarPageProps) {
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
          slotProps={{
            paper: {
              sx: {
                backgroundColor: "neutral.900",
                width: 256,
                height: "100vh",
              },
            },
          }}
          variant="persistent"
        >
          <ToolbarOffset />
          <UserSidebarContent close={null} data={data} />
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
}
