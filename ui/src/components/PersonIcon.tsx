import type { SvgIconProps } from "@mui/material/SvgIcon";
import SvgIcon from "@mui/material/SvgIcon";
import User from "react-feather/dist/icons/user";

export default function PersonIcon(props: SvgIconProps) {
  return (
    <SvgIcon {...props}>
      <User />
    </SvgIcon>
  );
}
