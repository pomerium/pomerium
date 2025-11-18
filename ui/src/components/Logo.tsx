import type { FC } from "react";
import React from "react";

const Logo: FC<{ src: string }> = ({ src }) => {
  return <img alt="Logo" src={src} height="30px" />;
};

export default Logo;
