import Logo from "./Logo";
import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Toolbar from "@mui/material/Toolbar";
import React, { FC } from "react";

const Header: FC = () => {
  return (
    <AppBar position="sticky">
      <Toolbar>
        <Logo />
        <Box flexGrow={1} />
        <Button variant="text" color="inherit">
          Logout
        </Button>
      </Toolbar>
    </AppBar>
  );
};
export default Header;
