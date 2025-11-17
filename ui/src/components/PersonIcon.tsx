import type { SvgIconProps } from "@mui/material";
import { SvgIcon } from "@mui/material";
import type { FC } from "react";
import React from "react";
import { User } from "react-feather";

export const PersonIcon: FC<SvgIconProps> = (props) => (
  <SvgIcon {...props}>
    <User />
  </SvgIcon>
);
export default PersonIcon;
