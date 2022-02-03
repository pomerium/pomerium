import SvgIcon, { SvgIconProps } from "@mui/material/SvgIcon";
import React, { FC } from "react";
import { User } from "react-feather";

export const PersonIcon: FC<SvgIconProps> = (props) => (
  <SvgIcon {...props}>
    <User />
  </SvgIcon>
);
export default PersonIcon;
