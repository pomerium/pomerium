import {
  Button,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from "@mui/material";
import React, { FC } from "react";

import { SignOutConfirmPageData } from "../types";

type SignOutConfirmPageProps = {
  data: SignOutConfirmPageData;
};
const SignOutConfirmPage: FC<SignOutConfirmPageProps> = ({ data }) => {
  function handleClickCancel(evt: React.MouseEvent) {
    evt.preventDefault();
    if (document.referrer) {
      location.href = document.referrer;
    } else {
      history.back();
    }
  }

  function handleClickLogout(evt: React.MouseEvent) {
    evt.preventDefault();
    location.href = data.url;
  }

  return (
    <Container>
      <Dialog open={true} disableEscapeKeyDown={true}>
        <DialogTitle>Logout?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to logout?
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClickCancel}>Cancel</Button>
          <Button onClick={handleClickLogout}>Logout</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};
export default SignOutConfirmPage;
