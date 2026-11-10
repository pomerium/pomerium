import Button from "@mui/material/Button";
import Container from "@mui/material/Container";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
import type { MouseEvent } from "react";

import type { SignOutConfirmPageData } from "../types";

type SignOutConfirmPageProps = {
  data: SignOutConfirmPageData;
};
export default function SignOutConfirmPage({ data }: SignOutConfirmPageProps) {
  function handleClickCancel(evt: MouseEvent) {
    evt.preventDefault();
    if (document.referrer) {
      location.href = document.referrer;
    } else {
      history.back();
    }
  }

  function handleClickLogout(evt: MouseEvent) {
    evt.preventDefault();
    location.href = data.url;
  }

  return (
    <Container>
      <Dialog open={true}>
        <DialogTitle>Logout?</DialogTitle>
        <DialogContent>
          <DialogContentText>Are you sure you want to logout?</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClickCancel}>Cancel</Button>
          <Button onClick={handleClickLogout}>Logout</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}
