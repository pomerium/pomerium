import type { AlertColor } from "@mui/material/Alert";
import Alert from "@mui/material/Alert";
import type { DialogProps } from "@mui/material/Dialog";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";
import type { ReactNode } from "react";

export type AlertDialogProps = DialogProps & {
  title?: ReactNode;
  severity?: AlertColor;
  actions?: ReactNode;
};
export default function AlertDialog({
  title,
  severity,
  children,
  actions,
  ...props
}: AlertDialogProps) {
  return (
    <Dialog transitionDuration={{ exit: 0 }} {...props}>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Alert severity={severity || "info"}>{children}</Alert>
      </DialogContent>
      {actions ? <DialogActions>{actions}</DialogActions> : <></>}
    </Dialog>
  );
}
