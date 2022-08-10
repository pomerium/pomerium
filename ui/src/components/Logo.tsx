import React from "react";
import type { FC } from "react";

const Logo: FC<{src: string}> = ({src}) => {
  return <img alt="Logo" src={src} height="30px" />;
};

export default Logo;
