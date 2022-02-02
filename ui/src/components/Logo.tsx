import LogoURL from "../static/logo_white.svg";
import React from "react";
import type { FC } from "react";

const Logo: FC = () => {
  return <img alt="Logo" src={LogoURL} height="30px" />;
};

export default Logo;
