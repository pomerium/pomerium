import Logo from "./Logo";
import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Toolbar from "@mui/material/Toolbar";
import React, {FC, useState} from "react";
import {useTheme} from "@mui/material/styles";
import {Drawer, IconButton, Menu, MenuItem, useMediaQuery} from "@mui/material";
import {ToolbarOffset} from "./ToolbarOffset";
import UserSidebarContent from "./UserSidebarContent";
import {ChevronLeft, ChevronRight, Menu as MenuIcon} from "react-feather";
import styled from "@mui/material/styles/styled";
import {Avatar} from "./Avatar";
import {PageData} from "../types";
import {get} from 'lodash';

const DrawerHeader = styled('div')(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  padding: theme.spacing(0, 1),
  justifyContent: 'flex-end',
}));

type HeaderProps = {
  includeSidebar: boolean;
  data: PageData;
};
const Header: FC<HeaderProps> = ({ includeSidebar, data }) => {
  const theme = useTheme();
  const mdUp = useMediaQuery(() => theme.breakpoints.up('md'), {
    defaultMatches: true,
    noSsr: false
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [anchorEl, setAnchorEl] = React.useState(null);
  const handleMenuOpen = e => {
    setAnchorEl(e.currentTarget);
  };
  const handleMenuClose = () => {
    setAnchorEl(null);
  };
  const userName = get(data, 'user.name') || get(data, 'user.claims.given_name');

  const handleDrawerOpen = () => {
    setDrawerOpen(true);
  };

  const handleDrawerClose = ():void => {
    setDrawerOpen(false);
  };

  const handleLogout = (evt: React.MouseEvent):void => {
    evt.preventDefault();
    location.href = "/.pomerium/sign_out";
  }

  return (
    <AppBar
      position="fixed"
      sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}
    >
      <Toolbar>
        {!mdUp && includeSidebar ? (
          <>
            <IconButton
              color="inherit"
              aria-label="open drawer"
              onClick={handleDrawerOpen}
              edge="start"
              sx={{ mr: 2, ...(drawerOpen && { display: 'none' }) }}
            >
              <MenuIcon />
            </IconButton>
            <Drawer
              sx={{
                width: 256,
                flexShrink: 0,
                '& .MuiDrawer-paper': {
                  width: 256,
                  boxSizing: 'border-box',
                  backgroundColor: 'neutral.900',
                  height: '100vh',
                },
              }}
              variant="persistent"
              anchor="left"
              open={drawerOpen}
            >
              <DrawerHeader>
                <IconButton onClick={handleDrawerClose}>
                  {theme.direction === 'ltr' ? <ChevronLeft /> : <ChevronRight />}
                </IconButton>
              </DrawerHeader>
              <UserSidebarContent close={handleDrawerClose}/>
              <ToolbarOffset />
            </Drawer>
          </>
        ) : (
          <a href="/.pomerium">
            <Logo />
          </a>
        )}
        <Box flexGrow={1} />
        {userName && (
          <>
            <IconButton color="inherit" onClick={handleMenuOpen}>
              <Avatar name={userName} url={get(data, 'claims.picture', null)} />
            </IconButton>
            <Menu
              onClose={handleMenuClose}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'center'
              }}
              keepMounted
              open={!!anchorEl}
              anchorEl={anchorEl}
            >
              <MenuItem onClick={handleLogout}>Logout</MenuItem>
            </Menu>
          </>
        )}
      </Toolbar>
    </AppBar>
  );
};
export default Header;
