import MuiAvatar from "@mui/material/Avatar";
import isArray from "lodash-es/isArray";
import User from "react-feather/dist/icons/user";

type AvatarProps = {
  name: string;
  url?: string;
};

export default function Avatar({ url, name }: AvatarProps) {
  if (isArray(url)) {
    url = url?.[0];
  }

  if (url === "https://graph.microsoft.com/v1.0/me/photo/$value") {
    url = undefined;
  }

  return url ? <MuiAvatar alt={name} src={url} /> : <User />;
}
