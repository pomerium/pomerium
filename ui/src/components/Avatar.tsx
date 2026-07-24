import { Avatar as MuiAvatar } from "@mui/material";
import { isArray } from "lodash-es";
import type { JSX } from "react";
import { User } from "react-feather";

type AvatarProps = {
  name: string;
  url?: string;
};

export const Avatar = ({ url, name }: AvatarProps): JSX.Element => {
  if (isArray(url)) {
    url = url?.[0];
  }

  if (url === "https://graph.microsoft.com/v1.0/me/photo/$value") {
    url = undefined;
  }

  return url ? <MuiAvatar alt={name} src={url} /> : <User />;
};
