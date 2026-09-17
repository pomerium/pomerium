import {
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from "@mui/material";
import type { FC } from "react";
import React from "react";

import type { SignOutConfirmPageData } from "../types";

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

  return (
    <Container>
      <Dialog open={true}>
        <Box component="form" action={data.url} method="POST">
          <DialogTitle>Logout?</DialogTitle>
          <DialogContent>
            <DialogContentText>
              Are you sure you want to logout?
            </DialogContentText>
            <FormControlLabel
              control={
                <Checkbox
                  name={data.reauth_enabled ? "allDevices" : undefined}
                  value="all"
                  defaultChecked={!data.reauth_enabled}
                  disabled={!data.reauth_enabled}
                />
              }
              label="Logout out everywhere"
              labelPlacement="end"
            />
            {!data.reauth_enabled && (
              <input type="hidden" name="allDevices" value="all" />
            )}
          </DialogContent>
          <DialogActions>
            <Button type="button" onClick={handleClickCancel}>
              Cancel
            </Button>
            <Button type="submit">Logout</Button>
          </DialogActions>
        </Box>
      </Dialog>
    </Container>
  );
};
export default SignOutConfirmPage;
