import CsrfInput from "./CsrfInput";
import Logo from "./Logo";
import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Toolbar from "@mui/material/Toolbar";
import React, { FC } from "react";

type HeaderProps = {
  csrfToken: string;
  signOutUrl: string;
};
const Header: FC<HeaderProps> = ({ csrfToken, signOutUrl }) => {
  return (
    <AppBar position="sticky">
      <Toolbar>
        <a href="/.pomerium">
          <Logo />
        </a>
        <Box flexGrow={1} />
        {signOutUrl ? (
          <form action={signOutUrl}>
            <CsrfInput csrfToken={csrfToken} />
            <Button variant="text" color="inherit" type="submit">
              Logout
            </Button>
          </form>
        ) : (
          <></>
        )}
      </Toolbar>
    </AppBar>
  );
};
export default Header;
