import CsrfInput from "./CsrfInput";
import Logo from "./Logo";
import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Toolbar from "@mui/material/Toolbar";
import React, { FC } from "react";

type HeaderProps = {};
const Header: FC<HeaderProps> = ({}) => {
  function handleClickLogout(evt: React.MouseEvent) {
    evt.preventDefault();
    location.href = "/.pomerium/sign_out";
  }

  return (
    <AppBar position="sticky">
      <Toolbar>
        <a href="/.pomerium">
          <Logo />
        </a>
        <Box flexGrow={1} />
        <Button variant="text" color="inherit" onClick={handleClickLogout}>
          Logout
        </Button>
      </Toolbar>
    </AppBar>
  );
};
export default Header;
