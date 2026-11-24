import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Drawer from "@mui/material/Drawer";
import IconButton from "@mui/material/IconButton";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
import { styled, useTheme } from "@mui/material/styles";
import Toolbar from "@mui/material/Toolbar";
import useMediaQuery from "@mui/material/useMediaQuery";
import get from "lodash-es/get";
import type { MouseEvent } from "react";
import { useState } from "react";
import ChevronLeft from "react-feather/dist/icons/chevron-left";
import ChevronRight from "react-feather/dist/icons/chevron-right";
import MenuIcon from "react-feather/dist/icons/menu";

import LogoURL from "../static/logo_white.svg";
import type { PageData } from "../types";
import Avatar from "./Avatar";
import Logo from "./Logo";
import ToolbarOffset from "./ToolbarOffset";
import UserSidebarContent from "./UserSidebarContent";

const DrawerHeader = styled("div")(({ theme }) => ({
  display: "flex",
  alignItems: "center",
  padding: theme.spacing(0, 1),
  justifyContent: "flex-end",
}));

type HeaderProps = {
  includeSidebar: boolean;
  data?: PageData;
};
export default function Header({ includeSidebar, data }: HeaderProps) {
  const theme = useTheme();
  const mdUp = useMediaQuery(() => theme.breakpoints.up("md"), {
    defaultMatches: true,
    noSsr: false,
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const handleMenuOpen = (e: MouseEvent<HTMLElement>) => {
    setAnchorEl(e.currentTarget);
  };
  const handleMenuClose = () => {
    setAnchorEl(null);
  };
  const userName = (get(data, "user.name") ||
    get(data, "user.claims.given_name") ||
    get(data, "profile.claims.name") ||
    get(data, "profile.claims.given_name") ||
    "") as string;
  const userPictureUrl = (get(data, "user.claims.picture") ||
    get(data, "profile.claims.picture") ||
    undefined) as string | undefined;
  const showAvatar = data?.page !== "SignOutConfirm" && data?.page !== "SignedOut";

  const handleDrawerOpen = () => {
    setDrawerOpen(true);
  };

  const handleDrawerClose = (): void => {
    setDrawerOpen(false);
  };

  const handleRoutes = (evt: MouseEvent): void => {
    evt.preventDefault();
    window.open("/.pomerium/routes");
  };

  const handleUserInfo = (evt: MouseEvent): void => {
    evt.preventDefault();
    window.open("/.pomerium/");
  };

  const handleLogout = (evt: MouseEvent): void => {
    evt.preventDefault();
    location.href = "/.pomerium/sign_out";
  };

  return (
    <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
      <Toolbar>
        {!mdUp && includeSidebar ? (
          <>
            <IconButton
              color="inherit"
              aria-label="open drawer"
              onClick={handleDrawerOpen}
              edge="start"
              sx={{ mr: 2, ...(drawerOpen && { display: "none" }) }}
            >
              <MenuIcon />
            </IconButton>
            <Drawer
              sx={{
                width: 256,
                flexShrink: 0,
                "& .MuiDrawer-paper": {
                  width: 256,
                  boxSizing: "border-box",
                  backgroundColor: "neutral.900",
                  height: "100vh",
                },
              }}
              variant="persistent"
              anchor="left"
              open={drawerOpen}
            >
              <DrawerHeader>
                <IconButton onClick={handleDrawerClose}>
                  {theme.direction === "ltr" ? <ChevronLeft /> : <ChevronRight />}
                </IconButton>
              </DrawerHeader>
              <UserSidebarContent close={handleDrawerClose} data={data} />
              <ToolbarOffset />
            </Drawer>
          </>
        ) : (
          <a href="/.pomerium">
            <Logo src={data?.logoUrl || LogoURL} />
          </a>
        )}
        <Box sx={{ flexGrow: 1 }} />
        {showAvatar && (
          <IconButton color="inherit" onClick={handleMenuOpen}>
            <Avatar name={userName} url={userPictureUrl} />
          </IconButton>
        )}
        <Menu
          onClose={handleMenuClose}
          anchorOrigin={{
            vertical: "bottom",
            horizontal: "center",
          }}
          keepMounted
          open={!!anchorEl}
          anchorEl={anchorEl}
        >
          <MenuItem onClick={handleUserInfo}>User Info</MenuItem>
          {data?.runtimeFlags?.routes_portal !== false && (
            <MenuItem onClick={handleRoutes}>Routes</MenuItem>
          )}
          <MenuItem onClick={handleLogout}>Logout</MenuItem>
        </Menu>
      </Toolbar>
    </AppBar>
  );
}
