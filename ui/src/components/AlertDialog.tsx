import {
  Alert,
  AlertColor,
  Dialog,
  DialogActions,
  DialogContent,
  DialogProps,
  DialogTitle,
} from "@mui/material";
import React, { FC } from "react";

export type AlertDialogProps = DialogProps & {
  title?: React.ReactNode;
  severity?: AlertColor;
  actions?: React.ReactNode;
};
export const AlertDialog: FC<AlertDialogProps> = ({
  title,
  severity,
  children,
  actions,
  ...props
}) => {
  return (
    <Dialog transitionDuration={{ exit: 0 }} {...props}>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Alert severity={severity || "info"}>{children}</Alert>
      </DialogContent>
      {actions ? <DialogActions>{actions}</DialogActions> : <></>}
    </Dialog>
  );
};
export default AlertDialog;
