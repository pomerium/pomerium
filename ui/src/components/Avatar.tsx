import React from 'react';
import {User} from "react-feather";
import MuiAvatar from "@mui/material/Avatar";

type AvatarProps = {
  name: string;
  url?: string;
}

export const Avatar = ({url, name}:AvatarProps): JSX.Element => {
  if (url === 'https://graph.microsoft.com/v1.0/me/photo/$value') {
    url = null;
  }

  return url ? (
    <MuiAvatar alt={name} src={url} />
  ) : (
    <User />
  );
};
