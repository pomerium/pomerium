import Button from "@mui/material/Button";
import Container from "@mui/material/Container";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
import styled from "@mui/material/styles/styled";
import React, { FC } from "react";
import { SignOutConfirmPageData } from "src/types";

type SignOutConfirmPageProps = {
  data: SignOutConfirmPageData;
};
const SignOutConfirmPage: FC<SignOutConfirmPageProps> = ({ data }) => {
  function handleClickCancel(evt: React.MouseEvent) {
    evt.preventDefault();
    history.back();
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
